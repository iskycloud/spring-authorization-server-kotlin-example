package com.example.service

import com.example.entity.AuthorizationConsentEntity
import com.example.repository.AuthorizationConsentRepository
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Component
import org.springframework.util.Assert
import org.springframework.util.StringUtils

@Component
class JpaOAuth2AuthorizationConsentService(
    authorizationConsentRepository: AuthorizationConsentRepository,
    registeredClientRepository: RegisteredClientRepository
) : OAuth2AuthorizationConsentService {
    private val authorizationConsentRepository: AuthorizationConsentRepository
    private val registeredClientRepository: RegisteredClientRepository

    init {
        Assert.notNull(authorizationConsentRepository, "authorizationConsentRepository cannot be null")
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null")
        this.authorizationConsentRepository = authorizationConsentRepository
        this.registeredClientRepository = registeredClientRepository
    }

    override fun save(authorizationConsent: OAuth2AuthorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null")
        authorizationConsentRepository.save<AuthorizationConsentEntity>(toEntity(authorizationConsent))
    }

    override fun remove(authorizationConsent: OAuth2AuthorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null")
        authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
            authorizationConsent.registeredClientId, authorizationConsent.principalName
        )
    }

    override fun findById(registeredClientId: String, principalName: String): OAuth2AuthorizationConsent? {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty")
        Assert.hasText(principalName, "principalName cannot be empty")
        return authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
            registeredClientId, principalName
        )?.let { authorizationConsentEntity: AuthorizationConsentEntity ->
            toObject(
                authorizationConsentEntity
            )
        }
    }

    private fun toObject(authorizationConsentEntity: AuthorizationConsentEntity): OAuth2AuthorizationConsent {
        val registeredClientId: String = authorizationConsentEntity.registeredClientId
        val registeredClient = registeredClientRepository.findById(registeredClientId)
            ?: throw DataRetrievalFailureException(
                "The RegisteredClient with id '$registeredClientId' was not found in the RegisteredClientRepository."
            )
        val builder = OAuth2AuthorizationConsent.withId(
            registeredClientId, authorizationConsentEntity.principalName
        )
        for (authority: String in StringUtils.commaDelimitedListToSet(authorizationConsentEntity.authorities)) {
            builder.authority(SimpleGrantedAuthority(authority))
        }
        return builder.build()
    }

    private fun toEntity(authorizationConsent: OAuth2AuthorizationConsent): AuthorizationConsentEntity {
        val registeredClientId = authorizationConsent.registeredClientId
        val principalName = authorizationConsent.principalName
        val authoritySet: MutableSet<String?> = HashSet()
        for (authority: GrantedAuthority in authorizationConsent.authorities) {
            authoritySet.add(authority.authority)
        }
        val authorities = StringUtils.collectionToCommaDelimitedString(authoritySet)

        return AuthorizationConsentEntity(
            registeredClientId = registeredClientId,
            principalName = principalName,
            authorities = authorities
        )
    }
}
