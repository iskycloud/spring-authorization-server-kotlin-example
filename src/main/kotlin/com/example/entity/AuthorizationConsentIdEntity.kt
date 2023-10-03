package com.example.entity

import java.io.Serializable

data class AuthorizationConsentIdEntity(
    val registeredClientId: String,
    val principalName: String,
) : Serializable
