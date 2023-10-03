package com.example.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/*
CREATE TABLE client (
    id varchar(255) NOT NULL,
    clientId varchar(255) NOT NULL,
    clientIdIssuedAt timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    clientSecret varchar(255) DEFAULT NULL,
    clientSecretExpiresAt timestamp DEFAULT NULL,
    clientName varchar(255) NOT NULL,
    clientAuthenticationMethods varchar(1000) NOT NULL,
    authorizationGrantTypes varchar(1000) NOT NULL,
    redirectUris varchar(1000) DEFAULT NULL,
    postLogoutRedirectUris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    clientSettings varchar(2000) NOT NULL,
    tokenSettings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);
 */

@Entity
@Table(name = "`client`")
data class ClientEntity(
    @Id
    var id: String,
    val clientId: String,
    val clientIdIssuedAt: Instant? = Instant.now(),
    val clientSecret: String? = null,
    val clientSecretExpiresAt: Instant? = null,
    val clientName: String,
    @Column(length = 1000)
    val clientAuthenticationMethods: String,
    @Column(length = 1000)
    val authorizationGrantTypes: String,
    @Column(length = 1000)
    val redirectUris: String? = null,
    @Column(length = 1000)
    val postLogoutRedirectUris: String? = null,
    @Column(length = 1000)
    val scopes: String,
    @Column(length = 2000)
    val clientSettings: String,
    @Column(length = 2000)
    val tokenSettings: String,
)
