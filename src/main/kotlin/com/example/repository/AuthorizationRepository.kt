package com.example.repository

import com.example.entity.AuthorizationEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface AuthorizationRepository: JpaRepository<AuthorizationEntity, String> {
    fun findByState(state: String?): AuthorizationEntity?
    fun findByAuthorizationCodeValue(authorizationCode: String?): AuthorizationEntity?
    fun findByAccessTokenValue(accessToken: String?): AuthorizationEntity?
    fun findByRefreshTokenValue(refreshToken: String?): AuthorizationEntity?
    fun findByOidcIdTokenValue(idToken: String?): AuthorizationEntity?
    fun findByUserCodeValue(userCode: String?): AuthorizationEntity?
    fun findByDeviceCodeValue(deviceCode: String?): AuthorizationEntity?

    @Query(
        "select a from AuthorizationEntity a where a.state = :token" +
                " or a.authorizationCodeValue = :token" +
                " or a.accessTokenValue = :token" +
                " or a.refreshTokenValue = :token" +
                " or a.oidcIdTokenValue = :token" +
                " or a.userCodeValue = :token" +
                " or a.deviceCodeValue = :token"
    )
    fun findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
        @Param("token") token: String?
    ): AuthorizationEntity?
}
