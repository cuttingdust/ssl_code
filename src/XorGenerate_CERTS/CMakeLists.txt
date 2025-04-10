cmake_minimum_required(VERSION 3.20)
get_filename_component(CURRENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)

project(${CURRENT_DIR})

# 设置生成证书的命令
add_custom_command(
    OUTPUT servert.crt servert.csr servert.key
    COMMAND openssl genpkey -algorithm RSA -out mykey.key -pkeyopt rsa_keygen_bits:2048
    COMMAND openssl req -new -key mykey.key -out mycert.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"
    COMMAND openssl x509 -req -days 365 -in mycert.csr -signkey mykey.key -out mycert.crt
    DEPENDS mykey.key
    COMMENT "Generating mykey.key, mycert.csr, and mycert.crt"
)

# 添加一个伪目标以便于生成
add_custom_target(${RROJECT_NAME} ALL DEPENDS servert.crt servert.csr servert.key)