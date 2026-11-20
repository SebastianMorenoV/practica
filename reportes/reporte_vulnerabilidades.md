# Reporte de Vulnerabilidades — Práctica 1 (Seguridad en APIs)

**Institución:** Instituto Tecnológico de Sonora (ITSON)  
**Programa:** Ingeniería en Software  
**Materia:** Ciberseguridad Aplicada  
**Unidad de Competencia:** UC3 — Seguridad de APIs y DevSecOps  
**Fecha:** Noviembre 2026  
**Sistema Evaluado:** `pedidos-api-vulnerable` (v1.0.0)  

---

## 1. Resumen de Hallazgos

| ID | Vulnerabilidad | Severidad | Referencia OWASP | Endpoint Afectado |
|---|---|---|---|---|
| **P1-001** | Broken Object Level Authorization (BOLA) en lectura | **Crítica** | OWASP API1:2023 | `GET /api/pedidos/{id}` |
| **P1-002** | BOLA en creación de recursos (BOLA de escritura) | **Alta** | OWASP API1:2023 | `POST /api/pedidos` |
| **P1-003** | Asignación masiva (Mass Assignment / BOPLA) para escalamiento de privilegios | **Alta** | OWASP API3:2023 | `POST /api/usuarios` |
| **P1-004** | Exposición excesiva de datos sensibles (contraseñas en texto plano) | **Crítica** | OWASP API3:2023 / API8:2023 | `GET /api/usuarios`, `GET /api/usuarios/{id}`, `GET /api/pedidos/{id}` |
| **P1-005** | Ausencia de validación estricta de esquemas de entrada | **Media** | OWASP API8:2023 | `POST /api/pedidos`, `POST /api/usuarios` |

---

## 2. Detalle de Vulnerabilidades

### P1-001: BOLA de lectura en pedidos (`GET /api/pedidos/{id}`)

- **Categoría OWASP:** API1:2023 — Broken Object Level Authorization (BOLA).
- **Severidad:** **Crítica** (CVSS estimado: 8.6)
  - *Justificación:* La explotación es trivial (basta cambiar un número en la URL). El impacto es severo, pues permite a cualquier usuario consultar pedidos ajenos, violando la confidencialidad de clientes e información financiera.
- **Descripción:**
  El controlador `PedidoController` en la versión vulnerable expone el método `obtenerPorId(@PathVariable Long id)`. Dicho método consulta directamente el repositorio `pedidoRepository.findById(id)` sin comprobar si el pedido recuperado pertenece al usuario que realiza la petición (simulado mediante la cabecera `X-User-Id`).
- **Evidencia de Explotación:**
  - **Contexto:** El usuario atacante es Beto (`X-User-Id: 2`). El pedido con ID `1` pertenece a Ana (`id: 1`).
  - **Petición HTTP:**
    ```http
    GET /api/pedidos/1 HTTP/1.1
    Host: localhost:8080
    X-User-Id: 2
    Accept: application/json
    ```
  - **Respuesta HTTP (200 OK):**
    ```json
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "id": 1,
      "descripcion": "Laptop para laboratorio",
      "monto": 18500.0,
      "fecha": "2026-09-01",
      "usuario": {
        "id": 1,
        "nombre": "Ana",
        "email": "ana@itson.mx",
        "password": "ana12345",
        "rol": "USER"
      }
    }
    ```
- **Impacto:** Fuga de información confidencial de compras y datos personales de otros clientes.
- **Remediación recomendada:** Implementar control de acceso a nivel de objeto resolviendo la identidad del solicitante y validando `pedido.getUsuario().getId().equals(usuarioAutenticado.getId())`. En caso de discrepancia, retornar `403 Forbidden`.

---

### P1-002: BOLA de escritura en creación de pedidos (`POST /api/pedidos`)

- **Categoría OWASP:** API1:2023 — Broken Object Level Authorization.
- **Severidad:** **Alta** (CVSS estimado: 7.5)
  - *Justificación:* Un usuario autenticado legítimo puede crear cargos, facturas o pedidos atribuidos a terceras personas manipulando el identificador del objeto anidado en el payload.
- **Descripción:**
  El endpoint `POST /api/pedidos` recibe directamente la entidad `Pedido` mediante `@RequestBody`. La entidad deserializa el campo anidado `usuario: { "id": X }` y lo almacena sin validar si coincide con el usuario autenticado.
- **Evidencia de Explotación:**
  - **Contexto:** El usuario Ana (`X-User-Id: 1`) crea un pedido por \$99,999.00 imputado a Beto (`usuario.id: 2`).
  - **Petición HTTP:**
    ```http
    POST /api/pedidos HTTP/1.1
    Host: localhost:8080
    X-User-Id: 1
    Content-Type: application/json

    {
      "descripcion": "Pedido inyectado a nombre de Beto",
      "monto": 99999.00,
      "fecha": "2026-11-11",
      "usuario": { "id": 2 }
    }
    ```
  - **Respuesta HTTP (201 Created / 200 OK):**
    ```json
    HTTP/1.1 200 OK
    Content-Type: application/json

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
- **Impacto:** Suplantación de identidad en transacciones de negocio, generación de deudas fraudulentas o afectación de balances de usuarios ajenos.
- **Remediación recomendada:** Emplear un DTO de creación (`PedidoCreacionDTO`) que excluya el campo `usuario`. El usuario dueño debe ser obtenido exclusivamente de la sesión/token autenticado en el servidor.

---

### P1-003: Mass Assignment en registro de usuarios (`POST /api/usuarios`)

- **Categoría OWASP:** API3:2023 — Broken Object Property Level Authorization (BOPLA / Mass Assignment).
- **Severidad:** **Alta** (CVSS estimado: 8.1)
  - *Justificación:* Permite a cualquier usuario no privilegiado autorregistrarse como administrador (`rol: "ADMIN"`), obteniendo acceso indebido a funciones privilegiadas.
- **Descripción:**
  `UsuarioController.registrar(@RequestBody Usuario usuario)` vincula las propiedades del JSON directamente sobre la entidad JPA `Usuario`. Jackson copia todas las propiedades que coinciden por nombre, permitiendo sobreescribir `rol` o fijar manualmente el `id`.
- **Evidencia de Explotación:**
  - **Petición HTTP:**
    ```http
    POST /api/usuarios HTTP/1.1
    Host: localhost:8080
    Content-Type: application/json

    {
      "nombre": "Eve Atacante",
      "email": "eve@atacante.mx",
      "password": "clave12345",
      "rol": "ADMIN",
      "id": 999
    }
    ```
  - **Respuesta HTTP (201 Created):**
    ```json
    HTTP/1.1 201 Created
    Content-Type: application/json

    {
      "id": 999,
      "nombre": "Eve Atacante",
      "email": "eve@atacante.mx",
      "password": "clave12345",
      "rol": "ADMIN"
    }
    ```
  - **Verificación posterior con `GET /api/usuarios/999`:**
    El registro persiste con rol administrativo `ADMIN`.
- **Impacto:** Escalamiento vertical de privilegios no autorizado; control administrativo total del sistema.
- **Remediación recomendada:** Usar un `UsuarioRegistroDTO` con únicamente los campos autorizados para el cliente (`nombre`, `email`, `password`). Asignar `rol = "USER"` de manera estricta e inmutable en el backend. Activar `fail-on-unknown-properties=true` en Jackson.

---

### P1-004: Exposición excesiva de datos sensibles (Passwords en texto plano)

- **Categoría OWASP:** API3:2023 / API8:2023.
- **Severidad:** **Crítica** (CVSS estimado: 9.1)
  - *Justificación:* Las credenciales de todos los usuarios se transmiten y muestran abiertamente en texto plano en todas las lecturas de usuarios y pedidos.
- **Descripción:**
  La entidad `Usuario` no cuenta con `@JsonIgnore` en su atributo `password`, ni se implementaron DTOs de salida. Las llamadas a `GET /api/usuarios` y `GET /api/pedidos/{id}` serializan la propiedad `password`.
- **Evidencia de Explotación:**
  - **Petición HTTP:**
    ```http
    GET /api/usuarios HTTP/1.1
    Host: localhost:8080
    ```
  - **Respuesta HTTP:**
    ```json
    [
      { "id": 1, "nombre": "Ana", "email": "ana@itson.mx", "password": "ana12345", "rol": "USER" },
      { "id": 2, "nombre": "Beto", "email": "beto@itson.mx", "password": "beto12345", "rol": "USER" }
    ]
    ```
- **Impacto:** Robo masivo de credenciales, compromiso de cuentas y pérdida total de privacidad.
- **Remediación recomendada:** Configurar `@JsonIgnore` en la entidad `Usuario` y retornar exclusivamente DTOs de lectura (`UsuarioRespuestaDTO`, `PedidoRespuestaDTO`) omitiendo credenciales y hashes.

---

### P1-005: Ausencia de validación estricta de esquemas de entrada

- **Categoría OWASP:** API8:2023 — Security Misconfiguration.
- **Severidad:** **Media** (CVSS estimado: 5.3)
  - *Justificación:* Permite inyectar información corrupta, montos absurdos/negativos, cadenas vacías o correos con formato no válido.
- **Descripción:**
  La API carece de la dependencia `spring-boot-starter-validation` y de anotaciones Bean Validation (`@Valid`, `@NotBlank`, `@Email`, `@Positive`, `@Size`).
- **Evidencia de Explotación:**
  Peticiones con montos negativos (`-500.00`) o emails sin formato (`"correo-invalido"`) son aceptadas y almacenadas con código HTTP `200/201`.
- **Impacto:** Inconsistencia de datos, posibles fallos en lógica financiera, ataques de abuso de parámetros.
- **Remediación recomendada:** Incluir `spring-boot-starter-validation`, anotar los DTOs con restricciones Bean Validation y manejar las excepciones en un `@RestControllerAdvice`.

