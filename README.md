# Servidor Proxy SOCKS5

## Características Implementadas

- Protocolo SOCKS5 completo (RFC 1928)
- Autenticación usuario/contraseña (RFC 1929)
- Soporte para direcciones IPv4, IPv6 y FQDN
- Resolución DNS asíncrona mediante threads
- Soporte para más de 500 conexiones concurrentes
- I/O no bloqueante mediante selector
- Sistema de roles (Administrador/Usuario)
- Protocolo de administración con autenticación
- Cliente de administración implementado en C
- Recolección de métricas en tiempo real
- Registro de accesos por usuario

## Requisitos

- GCC (C11)
- Make
- Sistema operativo: Linux / macOS

## Compilación

```bash
make clean
make all
```

Esto generará dos binarios:
- `socks5d` - Servidor proxy SOCKS5
- `admin-client` - Cliente de administración

## Uso

## Ejecución del Servidor

El servidor proxy SOCKS5 se ejecuta mediante el siguiente comando:

```bash
./socks5d [OPCIONES]
```

### Opciones de línea de comandos

```
-h                Imprime la ayuda y termina.
-l <SOCKS addr>   Dirección donde servirá el proxy SOCKS. (por defecto: 0.0.0.0)
                  Utilizar :: para modo dual-stack IPv6
-L <conf addr>    Dirección donde servirá el servicio de management/administración. (por defecto: 127.0.0.1)
-p <SOCKS port>   Puerto entrante conexiones SOCKS. (por defecto: 1080)
-P <conf port>    Puerto entrante conexiones configuración/management. (por defecto: 8080)
-u <name>:<pass>  Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.
-v                Imprime información sobre la versión y termina.
```

### Ejemplos de ejecución

Iniciar servidor en IPv4:
```bash
./socks5d -l 0.0.0.0 -p 1080
```

Iniciar servidor en modo dual-stack IPv4/IPv6:
```bash
./socks5d -l :: -p 1080
```

Iniciar servidor con configuración por defecto:
```bash
./socks5d
```

El servidor escuchará en dos puertos:
- Puerto SOCKS5: el especificado con la opción -p (por defecto 1080)
- Puerto de administración: 127.0.0.1:8080 (fijo, accesible únicamente desde localhost)

### Credenciales Iniciales

Al iniciar el servidor, se crea automáticamente un usuario administrador con las siguientes credenciales:

- Usuario: admin
- Contraseña: 1234
- Rol: Administrador

## Cliente de Administración

El cliente de administración permite gestionar el servidor de forma remota. Requiere autenticación obligatoria.

### Sintaxis

```bash
./admin-client -u <usuario> -P <contraseña> COMANDO [ARGUMENTOS]
```

### Opciones

```
-h <host>      Dirección del servidor de administración (por defecto: 127.0.0.1)
-p <puerto>    Puerto del servidor de administración (por defecto: 8080)
-u <usuario>   Usuario para autenticación
-P <contraseña> Contraseña para autenticación
```

### Comandos Disponibles

#### Comandos accesibles por todos los usuarios

```
metrics                          Muestra métricas del servidor
users                            Lista todos los usuarios registrados
conns                            Muestra las últimas conexiones registradas
```

#### Comandos exclusivos de administradores

```
add <usuario> <contraseña>              Agregar un nuevo usuario
del <usuario>                           Eliminar un usuario existente
change-password <usuario> <contraseña>  Cambiar contraseña de un usuario
change-role <usuario> <admin|user>      Cambiar rol de un usuario
```

Ejemplos:
```bash
./admin-client -u admin -P 1234 metrics

./admin-client -u admin -P 1234 users

./admin-client -u admin -P 1234 add john secret123

./admin-client -u admin -P 1234 change-role john admin

./admin-client -u admin -P 1234 del john

./admin-client -u admin -P 1234 conns
```

## Uso del Proxy SOCKS5

### Con curl

```bash
curl --proxy socks5://admin:1234@localhost:1080 http://google.com
```

Para resolución DNS remota:
```bash
curl --proxy socks5h://admin:1234@localhost:1080 http://google.com
```

## Sistema de Permisos

El sistema implementa dos roles de usuario con diferentes niveles de acceso.

### Rol Administrador

Los usuarios con rol de administrador tienen acceso completo a todas las funcionalidades:

- Consultar métricas del servidor
- Listar usuarios registrados
- Agregar nuevos usuarios
- Eliminar usuarios existentes
- Modificar contraseñas
- Cambiar roles de usuarios
- Consultar registros de conexiones

### Rol Usuario

Los usuarios con rol estándar tienen acceso limitado a las siguientes funcionalidades:

- Consultar métricas del servidor
- Listar usuarios registrados
- Consultar registros de conexiones

Los intentos de ejecutar comandos administrativos por parte de usuarios estándar son rechazados con el código de error correspondiente.

## Estructura del proyecto

```
.
├── src/
│   ├── admin/              # Protocolo de administración
│   │   ├── admin_server.c
│   │   ├── admin_auth.c
│   │   └── admin_commands.c
│   ├── auth/               # Autenticación SOCKS5
│   ├── dns/                # Resolución DNS asíncrona
│   ├── metrics/            # Métricas del servidor
│   ├── socks5/             # Protocolo SOCKS5
│   ├── users/              # Gestión de usuarios
│   ├── utils/              # Utilidades (selector, buffer, etc)
│   ├── main.c
│   └── admin_client.c      # Cliente de administración
├── tests/                  # Scripts de pruebas de rendimiento
│   ├── test_max_connections
│   ├── test_latency
│   ├── test_thoughput
│   └── Makefile
├── Makefile
└── README.md
```

## Protocolo de administración

El protocolo de administración requiere autenticación previa:

### Autenticación
```
Cliente → Servidor:
  VERSION | USER_LEN | USER | PASS_LEN | PASS
  
Servidor → Cliente:
  VERSION | STATUS
```

### Comandos
```
Cliente → Servidor:
  VERSION | COMMAND | LENGTH(2 bytes) | DATA
  
Servidor → Cliente:
  VERSION | STATUS | LENGTH(2 bytes) | DATA
```

Ver documentación completa en el informe -> SOON.

## Limitaciones conocidas

- Usuarios volátiles (se pierden al reiniciar el servidor)
- Máximo 100 usuarios 
- Sin persistencia de métricas
- Sin cifrado de credenciales 

## Pruebas

Los test de rendimiento se encuentran en la carpeta tests/

## Compilación
```bash
make clean
make all
```

Esto generará dos binarios de los tests:
- `test_max_connections`
- `test_latency` 
- `test_throughput`
```

## Uso

## Ejecución del Servidor

El servidor proxy SOCKS5 se ejecuta mediante el siguiente comando:

```bash
./socks5d -l 0.0.0.0 -p 1080 -P 8080 -u user:pass

Luego ejecutar el test deseado en otra terminal mediante:

```bash
./nombre_del_test user pass


## Información del Proyecto

Trabajo Práctico Especial
Protocolos de Comunicación (72.07)
Instituto Tecnológico de Buenos Aires (ITBA)
Segundo Cuatrimestre 2025

### Autores

- Sebastián Caules - Legajo 64331
- Alexis Herrera Vegas - Legajo 64045
- Andrés Cortese - Legajo 64612
- Tomás Jerónimo Esquivel - Legajo 64756