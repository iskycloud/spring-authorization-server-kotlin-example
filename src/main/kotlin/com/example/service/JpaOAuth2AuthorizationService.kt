package com.example.service

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.Module
import com.fasterxml.jackson.databind.ObjectMapper
import com.example.entity.AuthorizationEntity
import com.example.repository.AuthorizationRepository
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module
import org.springframework.stereotype.Component
import org.springframework.util.Assert
import org.springframework.util.StringUtils
import java.time.Instant
import java.util.function.Consumer
import java.util.function.Function

@Component
class JpaOAuth2AuthorizationService(
    authorizationRepository: AuthorizationRepository,
    registeredClientRepository: RegisteredClientRepository
) : OAuth2AuthorizationService {
    private val authorizationRepository: AuthorizationRepository
    private val registeredClientRepository: RegisteredClientRepository
    private val objectMapper = ObjectMapper()

    init {
        Assert.notNull(authorizationRepository, "authorizationRepository cannot be null")
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null")
        this.authorizationRepository = authorizationRepository
        this.registeredClientRepository = registeredClientRepository
        val classLoader = JpaOAuth2AuthorizationService::class.java.getClassLoader()
        val securityModules: List<Module> = SecurityJackson2Modules.getModules(classLoader)
        objectMapper.registerModules(securityModules)
        objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
    }

    override fun save(authorization: OAuth2Authorization) {
        Assert.notNull(authorization, "authorization cannot be null")
        authorizationRepository.save<AuthorizationEntity>(toEntity(authorization))
    }

    override fun remove(authorization: OAuth2Authorization) {
        Assert.notNull(authorization, "authorization cannot be null")
        authorizationRepository.deleteById(authorization.id)
    }

    override fun findById(id: String): OAuth2Authorization? {
        Assert.hasText(id, "id cannot be empty")
        return authorizationRepository.findById(id).map(Function { authorizationEntity: AuthorizationEntity ->
            toObject(
                authorizationEntity
            )
        }).orElse(null)
    }

    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        Assert.hasText(token, "token cannot be empty")
        val result: AuthorizationEntity?
        result = if (tokenType == null) {
            authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
                token
            )
        } else if (OAuth2ParameterNames.STATE == tokenType.value) {
            authorizationRepository.findByState(token)
        } else if (OAuth2ParameterNames.CODE == tokenType.value) {
            authorizationRepository.findByAuthorizationCodeValue(token)
        } else if (OAuth2ParameterNames.ACCESS_TOKEN == tokenType.value) {
            authorizationRepository.findByAccessTokenValue(token)
        } else if (OAuth2ParameterNames.REFRESH_TOKEN == tokenType.value) {
            authorizationRepository.findByRefreshTokenValue(token)
        } else if (OidcParameterNames.ID_TOKEN == tokenType.value) {
            authorizationRepository.findByOidcIdTokenValue(token)
        } else if (OAuth2ParameterNames.USER_CODE == tokenType.value) {
            authorizationRepository.findByUserCodeValue(token)
        } else if (OAuth2ParameterNames.DEVICE_CODE == tokenType.value) {
            authorizationRepository.findByDeviceCodeValue(token)
        } else {
            null
        }
        return result?.let { authorizationEntity: AuthorizationEntity -> toObject(authorizationEntity) }
    }

    private fun toObject(authorizationEntity: AuthorizationEntity): OAuth2Authorization {
        val registeredClient = registeredClientRepository.findById(authorizationEntity.registeredClientId)
            ?: throw DataRetrievalFailureException(
                "The RegisteredClient with id '${authorizationEntity.registeredClientId}' was not found in the RegisteredClientRepository."
            )
        val builder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .id(authorizationEntity.id)
            .principalName(authorizationEntity.principalName)
            .authorizationGrantType(resolveAuthorizationGrantType(authorizationEntity.authorizationGrantType))
            .authorizedScopes(StringUtils.commaDelimitedListToSet(authorizationEntity.authorizedScopes))
            .attributes { attributes: MutableMap<String?, Any?> ->
                attributes.putAll(
                    parseMap(authorizationEntity.attributes)
                )
            }
        if (authorizationEntity.state != null) {
            builder.attribute(OAuth2ParameterNames.STATE, authorizationEntity.state)
        }
        if (authorizationEntity.authorizationCodeValue != null) {
            val authorizationCode = OAuth2AuthorizationCode(
                authorizationEntity.authorizationCodeValue,
                authorizationEntity.authorizationCodeIssuedAt,
                authorizationEntity.authorizationCodeExpiresAt
            )
            builder.token(
                authorizationCode
            ) { metadata: MutableMap<String?, Any?> ->
                metadata.putAll(
                    parseMap(authorizationEntity.authorizationCodeMetadata)
                )
            }
        }
        if (authorizationEntity.accessTokenValue != null) {
            val accessToken = OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                authorizationEntity.accessTokenValue,
                authorizationEntity.accessTokenIssuedAt,
                authorizationEntity.accessTokenExpiresAt,
                StringUtils.commaDelimitedListToSet(authorizationEntity.accessTokenScopes)
            )
            builder.token(
                accessToken
            ) { metadata: MutableMap<String?, Any?> ->
                metadata.putAll(
                    parseMap(authorizationEntity.accessTokenMetadata)
                )
            }
        }
        if (authorizationEntity.refreshTokenValue != null) {
            val refreshToken = OAuth2RefreshToken(
                authorizationEntity.refreshTokenValue,
                authorizationEntity.refreshTokenIssuedAt,
                authorizationEntity.refreshTokenExpiresAt
            )
            builder.token(
                refreshToken
            ) { metadata: MutableMap<String?, Any?> ->
                metadata.putAll(
                    parseMap(authorizationEntity.refreshTokenMetadata)
                )
            }
        }
        if (authorizationEntity.oidcIdTokenValue != null) {
            val idToken = OidcIdToken(
                authorizationEntity.oidcIdTokenValue,
                authorizationEntity.oidcIdTokenIssuedAt,
                authorizationEntity.oidcIdTokenExpiresAt,
                parseMap(authorizationEntity.oidcIdTokenClaims)
            )
            builder.token(
                idToken
            ) { metadata: MutableMap<String?, Any?> ->
                metadata.putAll(
                    parseMap(authorizationEntity.oidcIdTokenMetadata)
                )
            }
        }
        if (authorizationEntity.userCodeValue != null) {
            val userCode = OAuth2UserCode(
                authorizationEntity.userCodeValue,
                authorizationEntity.userCodeIssuedAt,
                authorizationEntity.userCodeExpiresAt
            )
            builder.token(
                userCode
            ) { metadata: MutableMap<String?, Any?> ->
                metadata.putAll(
                    parseMap(authorizationEntity.userCodeMetadata)
                )
            }
        }
        if (authorizationEntity.deviceCodeValue != null) {
            val deviceCode = OAuth2DeviceCode(
                authorizationEntity.deviceCodeValue,
                authorizationEntity.deviceCodeIssuedAt,
                authorizationEntity.deviceCodeExpiresAt
            )
            builder.token(
                deviceCode
            ) { metadata: MutableMap<String?, Any?> ->
                metadata.putAll(
                    parseMap(authorizationEntity.deviceCodeMetadata)
                )
            }
        }
        return builder.build()
    }

    private fun toEntity(authorization: OAuth2Authorization): AuthorizationEntity {
        val authorizationEntity = AuthorizationEntity(
            id = authorization.id,
            registeredClientId = authorization.registeredClientId,
            principalName = authorization.principalName,
            authorizationGrantType = authorization.authorizationGrantType.value,
        )
        authorizationEntity.authorizedScopes =
            StringUtils.collectionToDelimitedString(authorization.authorizedScopes, ",")
        authorizationEntity.attributes = writeMap(authorization.attributes)
        authorizationEntity.state = authorization.getAttribute(OAuth2ParameterNames.STATE)
        val authorizationCode = authorization.getToken(
            OAuth2AuthorizationCode::class.java
        )
        setTokenValues(
            authorizationCode,
            authorizationEntity::authorizationCodeValue::set,
            authorizationEntity::authorizationCodeIssuedAt::set,
            authorizationEntity::authorizationCodeExpiresAt::set,
            authorizationEntity::authorizationCodeMetadata::set
        )
        val accessToken = authorization.getToken(
            OAuth2AccessToken::class.java
        )
        setTokenValues(
            accessToken,
            authorizationEntity::accessTokenValue::set,
            authorizationEntity::accessTokenIssuedAt::set,
            authorizationEntity::accessTokenExpiresAt::set,
            authorizationEntity::accessTokenMetadata::set
        )
        if (accessToken != null && accessToken.token.scopes != null) {
            authorizationEntity.accessTokenScopes =
                StringUtils.collectionToDelimitedString(accessToken.token.scopes, ",")
        }
        val refreshToken = authorization.getToken(
            OAuth2RefreshToken::class.java
        )
        setTokenValues(
            refreshToken,
            authorizationEntity::refreshTokenValue::set,
            authorizationEntity::refreshTokenIssuedAt::set,
            authorizationEntity::refreshTokenExpiresAt::set,
            authorizationEntity::refreshTokenMetadata::set
        )
        val oidcIdToken = authorization.getToken(OidcIdToken::class.java)
        setTokenValues(
            oidcIdToken,
            authorizationEntity::oidcIdTokenValue::set,
            authorizationEntity::oidcIdTokenIssuedAt::set,
            authorizationEntity::oidcIdTokenExpiresAt::set,
            authorizationEntity::oidcIdTokenMetadata::set
        )
        if (oidcIdToken != null) {
            authorizationEntity.oidcIdTokenClaims = writeMap(oidcIdToken.claims)
        }
        val userCode = authorization.getToken(
            OAuth2UserCode::class.java
        )
        setTokenValues(
            userCode,
            authorizationEntity::userCodeValue::set,
            authorizationEntity::userCodeIssuedAt::set,
            authorizationEntity::userCodeExpiresAt::set,
            authorizationEntity::userCodeMetadata::set
        )
        val deviceCode = authorization.getToken(
            OAuth2DeviceCode::class.java
        )
        setTokenValues(
            deviceCode,
            authorizationEntity::deviceCodeValue::set,
            authorizationEntity::deviceCodeIssuedAt::set,
            authorizationEntity::deviceCodeExpiresAt::set,
            authorizationEntity::deviceCodeMetadata::set
        )
        return authorizationEntity
    }

    private fun setTokenValues(
        token: OAuth2Authorization.Token<*>?,
        tokenValueConsumer: Consumer<String>,
        issuedAtConsumer: Consumer<Instant?>,
        expiresAtConsumer: Consumer<Instant?>,
        metadataConsumer: Consumer<String>
    ) {
        if (token != null) {
            val oAuth2Token = token.token
            tokenValueConsumer.accept(oAuth2Token.tokenValue)
            issuedAtConsumer.accept(oAuth2Token.issuedAt)
            expiresAtConsumer.accept(oAuth2Token.expiresAt)
            metadataConsumer.accept(writeMap(token.metadata))
        }
    }

    private fun parseMap(data: String?): Map<String?, Any?> {
        return try {
            objectMapper.readValue(data, object : TypeReference<Map<String?, Any?>>() {})
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex.message, ex)
        }
    }

    private fun writeMap(metadata: Map<String, Any>?): String {
        return try {
            objectMapper.writeValueAsString(metadata)
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
            } else if (AuthorizationGrantType.DEVICE_CODE.value == authorizationGrantType) {
                return AuthorizationGrantType.DEVICE_CODE
            }
            return AuthorizationGrantType(authorizationGrantType) // Custom authorization grant type
        }
    }
}

