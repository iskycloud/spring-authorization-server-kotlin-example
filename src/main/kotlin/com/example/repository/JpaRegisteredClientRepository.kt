package com.example.repository

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.example.entity.ClientEntity
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Component
import org.springframework.util.Assert
import org.springframework.util.StringUtils
import java.util.function.Consumer
import java.util.function.Function

@Component
class JpaRegisteredClientRepository(clientRepository: ClientRepository) : RegisteredClientRepository {
    private val clientRepository: ClientRepository
    private val objectMapper = ObjectMapper()

    init {
        Assert.notNull(clientRepository, "clientRepository cannot be null")
        this.clientRepository = clientRepository
        val classLoader = JpaRegisteredClientRepository::class.java.getClassLoader()
        val securityModules = SecurityJackson2Modules.getModules(classLoader)
        objectMapper.registerModules(securityModules)
        objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
    }

    override fun save(registeredClient: RegisteredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null")
        clientRepository.save<ClientEntity>(toEntity(registeredClient))
    }

    override fun findById(id: String): RegisteredClient? {
        Assert.hasText(id, "id cannot be empty")
        return clientRepository.findById(id).map(Function { clientEntity: ClientEntity ->
            toObject(
                clientEntity
            )
        }).orElse(null)
    }

    override fun findByClientId(clientId: String): RegisteredClient? {
        Assert.hasText(clientId, "clientId cannot be empty")
        return clientRepository.findByClientId(clientId)?.let { clientEntity: ClientEntity -> toObject(clientEntity) }
    }

    private fun toObject(clientEntity: ClientEntity): RegisteredClient {
        val clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(
            clientEntity.clientAuthenticationMethods
        )
        val authorizationGrantTypes = StringUtils.commaDelimitedListToSet(
            clientEntity.authorizationGrantTypes
        )
        val redirectUris = StringUtils.commaDelimitedListToSet(
            clientEntity.redirectUris
        )
        val postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(
            clientEntity.postLogoutRedirectUris
        )
        val clientScopes = StringUtils.commaDelimitedListToSet(
            clientEntity.scopes
        )
        val builder = RegisteredClient.withId(clientEntity.id)
            .clientId(clientEntity.clientId)
            .clientIdIssuedAt(clientEntity.clientIdIssuedAt)
            .clientSecret(clientEntity.clientSecret)
            .clientSecretExpiresAt(clientEntity.clientSecretExpiresAt)
            .clientName(clientEntity.clientName)
            .clientAuthenticationMethods { authenticationMethods: MutableSet<ClientAuthenticationMethod?> ->
                clientAuthenticationMethods.forEach(
                    Consumer { authenticationMethod: String ->
                        authenticationMethods.add(
                            resolveClientAuthenticationMethod(authenticationMethod)
                        )
                    })
            }
            .authorizationGrantTypes { grantTypes: MutableSet<AuthorizationGrantType?> ->
                authorizationGrantTypes.forEach(
                    Consumer { grantType: String ->
                        grantTypes.add(
                            resolveAuthorizationGrantType(grantType)
                        )
                    })
            }
            .redirectUris { uris: MutableSet<String?> ->
                uris.addAll(
                    redirectUris
                )
            }
            .postLogoutRedirectUris { uris: MutableSet<String?> ->
                uris.addAll(
                    postLogoutRedirectUris
                )
            }
            .scopes { scopes: MutableSet<String?> ->
                scopes.addAll(
                    clientScopes
                )
            }
        val clientSettingsMap = parseMap(clientEntity.clientSettings)
        builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build())
        val tokenSettingsMap = parseMap(clientEntity.tokenSettings)
        builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build())
        return builder.build()
    }

    private fun toEntity(registeredClient: RegisteredClient): ClientEntity {
        val clientAuthenticationMethods: MutableList<String?> =
            ArrayList(registeredClient.clientAuthenticationMethods.size)
        registeredClient.clientAuthenticationMethods.forEach(Consumer { clientAuthenticationMethod: ClientAuthenticationMethod ->
            clientAuthenticationMethods.add(
                clientAuthenticationMethod.value
            )
        })
        val authorizationGrantTypes: MutableList<String?> = ArrayList(registeredClient.authorizationGrantTypes.size)
        registeredClient.authorizationGrantTypes.forEach(Consumer { authorizationGrantType: AuthorizationGrantType ->
            authorizationGrantTypes.add(
                authorizationGrantType.value
            )
        })
        val clientEntity = ClientEntity(
            id = registeredClient.id,
            clientId = registeredClient.clientId,
            clientIdIssuedAt = registeredClient.clientIdIssuedAt,
            clientSecret = registeredClient.clientSecret,
            clientSecretExpiresAt = registeredClient.clientSecretExpiresAt,
            clientName = registeredClient.clientName,
            clientAuthenticationMethods = StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods),
            authorizationGrantTypes = StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes),
            redirectUris = StringUtils.collectionToCommaDelimitedString(registeredClient.redirectUris),
            postLogoutRedirectUris = StringUtils.collectionToCommaDelimitedString(registeredClient.postLogoutRedirectUris),
            scopes = StringUtils.collectionToCommaDelimitedString(registeredClient.scopes),
            clientSettings = writeMap(registeredClient.clientSettings.settings),
            tokenSettings = writeMap(registeredClient.tokenSettings.settings),
        )
        return clientEntity
    }

    private fun parseMap(data: String): Map<String?, Any?> {
        return try {
            objectMapper.readValue(data, object : TypeReference<Map<String?, Any?>>() {})
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun writeMap(data: Map<String, Any>): String {
        return try {
            objectMapper.writeValueAsString(data)
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    companion object {
        private fun resolveAuthorizationGrantType(authorizationGrantType: String): AuthorizationGrantType {
            if (AuthorizationGrantType.AUTHORIZATION_CODE.value == authorizationGrantType) {
                return AuthorizationGrantType.AUTHORIZATION_CODE
            } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.value == authorizationGrantType) {
                return AuthorizationGrantType.CLIENT_CREDENTIALS
            } else if (AuthorizationGrantType.REFRESH_TOKEN.value == authorizationGrantType) {
                return AuthorizationGrantType.REFRESH_TOKEN
            }
            return AuthorizationGrantType(authorizationGrantType) // Custom authorization grant type
        }

        private fun resolveClientAuthenticationMethod(clientAuthenticationMethod: String): ClientAuthenticationMethod {
            if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.value == clientAuthenticationMethod) {
                return ClientAuthenticationMethod.CLIENT_SECRET_BASIC
            } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.value == clientAuthenticationMethod) {
                return ClientAuthenticationMethod.CLIENT_SECRET_POST
            } else if (ClientAuthenticationMethod.NONE.value == clientAuthenticationMethod) {
                return ClientAuthenticationMethod.NONE
            }
            return ClientAuthenticationMethod(clientAuthenticationMethod) // Custom client authentication method
        }
    }
}
