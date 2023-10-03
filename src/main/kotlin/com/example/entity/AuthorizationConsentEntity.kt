package com.example.entity

import jakarta.persistence.*

/*
CREATE TABLE authorizationConsent (
    registeredClientId varchar(255) NOT NULL,
    principalName varchar(255) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registeredClientId, principalName)
);
 */

@Entity
@Table(name = "`authorizationConsent`")
@IdClass(AuthorizationConsentIdEntity::class)
data class AuthorizationConsentEntity(
    @Id
    val registeredClientId: String,
    @Id
    val principalName: String,
    @Column(length = 1000)
    val authorities: String,
)
