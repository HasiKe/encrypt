# Test-Konfiguration
enable_testing()

# Crypto-Tests
add_executable(crypto_test crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE encrypt_core)

# Test hinzufügen
add_test(NAME CryptoTest COMMAND crypto_test)