package com.example.repository

import com.example.entity.ClientEntity
import org.springframework.data.jpa.repository.JpaRepository

interface ClientRepository: JpaRepository<ClientEntity, String> {
    fun findByClientId(clientId: String?): ClientEntity?
}
