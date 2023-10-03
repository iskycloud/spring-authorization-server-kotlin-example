package com.example.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/*
CREATE TABLE authorization (
    id varchar(255) NOT NULL,
    registeredClientId varchar(255) NOT NULL,
    principalName varchar(255) NOT NULL,
    authorizationGrantType varchar(255) NOT NULL,
    authorizedScopes varchar(1000) DEFAULT NULL,
    attributes varchar(4000) DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorizationCodeValue varchar(4000) DEFAULT NULL,
    authorizationCodeIssuedAt timestamp DEFAULT NULL,
    authorizationCodeExpiresAt timestamp DEFAULT NULL,
    authorizationCodeMetadata varchar(2000) DEFAULT NULL,
    accessTokenValue varchar(4000) DEFAULT NULL,
    accessTokenIssuedAt timestamp DEFAULT NULL,
    accessTokenExpiresAt timestamp DEFAULT NULL,
    accessTokenMetadata varchar(2000) DEFAULT NULL,
    accessTokenType varchar(255) DEFAULT NULL,
    accessTokenScopes varchar(1000) DEFAULT NULL,
    refreshTokenValue varchar(4000) DEFAULT NULL,
    refreshTokenIssuedAt timestamp DEFAULT NULL,
    refreshTokenExpiresAt timestamp DEFAULT NULL,
    refreshTokenMetadata varchar(2000) DEFAULT NULL,
    oidcIdTokenValue varchar(4000) DEFAULT NULL,
    oidcIdTokenIssuedAt timestamp DEFAULT NULL,
    oidcIdTokenExpiresAt timestamp DEFAULT NULL,
    oidcIdTokenMetadata varchar(2000) DEFAULT NULL,
    oidcIdTokenClaims varchar(2000) DEFAULT NULL,
    userCodeValue varchar(4000) DEFAULT NULL,
    userCodeIssuedAt timestamp DEFAULT NULL,
    userCodeExpiresAt timestamp DEFAULT NULL,
    userCodeMetadata varchar(2000) DEFAULT NULL,
    deviceCodeValue varchar(4000) DEFAULT NULL,
    deviceCodeIssuedAt timestamp DEFAULT NULL,
    deviceCodeExpiresAt timestamp DEFAULT NULL,
    deviceCodeMetadata varchar(2000) DEFAULT NULL,
    PRIMARY KEY (id)
);
 */

@Entity
@Table(name = "`authorization`")
data class AuthorizationEntity (
    @Id
    @Column
    val id: String,
    val registeredClientId: String,
    val principalName: String,
    val authorizationGrantType: String,
    @Column(length = 1000)
    var authorizedScopes: String? = null,
    @Column(length = 4000)
    var attributes: String? = null,
    @Column(length = 500)
    var state: String? = null,

    @Column(length = 4000)
    var authorizationCodeValue: String? = null,
    var authorizationCodeIssuedAt: Instant? = null,
    var authorizationCodeExpiresAt: Instant? = null,
    var authorizationCodeMetadata: String? = null,

    @Column(length = 4000)
    var accessTokenValue: String? = null,
    var accessTokenIssuedAt: Instant? = null,
    var accessTokenExpiresAt: Instant? = null,
    @Column(length = 2000)
    var accessTokenMetadata: String? = null,
    var accessTokenType: String? = null,
    @Column(length = 1000)
    var accessTokenScopes: String? = null,

    @Column(length = 4000)
    var refreshTokenValue: String? = null,
    var refreshTokenIssuedAt: Instant? = null,
    var refreshTokenExpiresAt: Instant? = null,
    @Column(length = 2000)
    var refreshTokenMetadata: String? = null,

    @Column(length = 4000)
    var oidcIdTokenValue: String? = null,
    var oidcIdTokenIssuedAt: Instant? = null,
    var oidcIdTokenExpiresAt: Instant? = null,
    @Column(length = 2000)
    var oidcIdTokenMetadata: String? = null,
    @Column(length = 2000)
    var oidcIdTokenClaims: String? = null,

    @Column(length = 4000)
    var userCodeValue: String? = null,
    var userCodeIssuedAt: Instant? = null,
    var userCodeExpiresAt: Instant? = null,
    @Column(length = 2000)
    var userCodeMetadata: String? = null,

    @Column(length = 4000)
    var deviceCodeValue: String? = null,
    var deviceCodeIssuedAt: Instant? = null,
    var deviceCodeExpiresAt: Instant? = null,
    @Column(length = 2000)
    var deviceCodeMetadata: String? = null,
)
