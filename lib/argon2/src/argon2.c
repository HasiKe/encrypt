#include "argon2.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* 
 * Vereinfachte Implementierung von Argon2 für Testzwecke
 * In einer echten Anwendung sollte die vollständige Argon2-Bibliothek verwendet werden
 */

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash, const size_t hashlen) {
    
    if (hash == NULL || hashlen == 0) {
        return ARGON2_OUTPUT_PTR_NULL;
    }
    
    if (pwd == NULL && pwdlen > 0) {
        return ARGON2_PWD_PTR_MISMATCH;
    }
    
    if (salt == NULL && saltlen > 0) {
        return ARGON2_SALT_PTR_MISMATCH;
    }
    
    if (t_cost < ARGON2_MIN_TIME_COST) {
        return ARGON2_TIME_TOO_SMALL;
    }
    
    if (m_cost < ARGON2_MIN_MEMORY) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }
    
    // Für Testzwecke: Einfache Implementierung basierend auf PBKDF2-Simulation
    // In einer echten Anwendung würde hier der tatsächliche Argon2-Algorithmus stehen
    
    // Einfacher Schlüsselableitungsalgorithmus für Tests
    uint8_t *buf = (uint8_t *)hash;
    const uint8_t *salt_buf = (const uint8_t *)salt;
    const uint8_t *pwd_buf = (const uint8_t *)pwd;
    
    // Initialisiere das Ergebnis mit dem Salz
    for (size_t i = 0; i < hashlen; i++) {
        buf[i] = (i < saltlen) ? salt_buf[i] : 0;
    }
    
    // Simuliere mehrere Runden für die Kostenfaktoren
    for (uint32_t r = 0; r < t_cost; r++) {
        for (size_t i = 0; i < hashlen; i++) {
            uint8_t byte = buf[i];
            
            // Mische mit dem Passwort
            for (size_t j = 0; j < pwdlen; j++) {
                byte ^= pwd_buf[j];
                byte = (byte << 1) | (byte >> 7); // Einfache Rotation
            }
            
            // Mische mit der Iteration und Position
            byte ^= (r & 0xFF);
            byte ^= (i & 0xFF);
            
            buf[i] = byte;
        }
    }
    
    return ARGON2_OK;
}

const char *argon2_error_message(int error_code) {
    switch (error_code) {
        case ARGON2_OK:
            return "OK";
        case ARGON2_OUTPUT_PTR_NULL:
            return "Output pointer is NULL";
        case ARGON2_OUTPUT_TOO_SHORT:
            return "Output is too short";
        case ARGON2_PWD_TOO_SHORT:
            return "Password is too short";
        case ARGON2_PWD_PTR_MISMATCH:
            return "Password pointer mismatch";
        case ARGON2_SALT_PTR_MISMATCH:
            return "Salt pointer mismatch";
        case ARGON2_TIME_TOO_SMALL:
            return "Time cost is too small";
        case ARGON2_MEMORY_TOO_LITTLE:
            return "Memory cost is too little";
        default:
            return "Unknown error code";
    }
}