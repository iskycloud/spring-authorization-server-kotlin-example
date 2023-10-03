package com.example.repository

import com.example.entity.AuthorizationConsentEntity
import com.example.entity.AuthorizationConsentIdEntity
import org.springframework.data.jpa.repository.JpaRepository

interface AuthorizationConsentRepository: JpaRepository<AuthorizationConsentEntity, AuthorizationConsentIdEntity> {
    fun findByRegisteredClientIdAndPrincipalName(
        registeredClientId: String?,
        principalName: String?
    ): AuthorizationConsentEntity?

    fun deleteByRegisteredClientIdAndPrincipalName(registeredClientId: String?, principalName: String?)
}
