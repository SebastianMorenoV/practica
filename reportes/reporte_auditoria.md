# Reporte de Auditoría de Seguridad en APIs — Práctica 1

**Organización / Institución:** Instituto Tecnológico de Sonora (ITSON)  
**Programa Educativo:** Ingeniería en Software  
**Curso:** Ciberseguridad Aplicada  
**Unidad de Competencia:** UC3 — Seguridad de APIs y DevSecOps  
**Fecha de Evaluación:** Noviembre 2026  
**Versión de Informe:** 1.0 Final  
**Objetivo de Evaluación:** Auditoría de vulnerabilidades BOLA, Mass Assignment y Validación de Esquemas en API REST de Pedidos.

---

## 1. Resumen Ejecutivo

El presente informe detalla los resultados de la auditoría de seguridad y análisis de vulnerabilidades aplicada sobre el sistema **API REST de Gestión de Pedidos** (versión original `pedidos-api-vulnerable` y versión remediada `pedidos-api-seguro`), desarrollada sobre Spring Boot 3.3.x y Java 17.

Durante la fase de reconocimiento y explotación sobre la versión base se identificaron fallas críticas de seguridad correspondientes a las categorías principales del estándar **OWASP API Security Top 10 (2023)**:
- Acceso desautorizado a recursos ajenos (**API1:2023 - BOLA**), permitiendo a cualquier usuario consultar y crear pedidos a nombre de otros clientes.
- Asignación masiva (**API3:2023 - BOPLA / Mass Assignment**), que posibilitó el escalamiento vertical no autorizado a privilegios de Administrador (`ADMIN`).
- Exposición total de credenciales de usuario en texto plano en las respuestas JSON.
- Carencia de validaciones sintácticas y semánticas sobre entradas de usuario (**API8:2023**).

Posteriormente se procedió con la fase de remediación mediante la implementación de patrones de arquitectura segura: desacoplamiento con DTOs, validación de esquemas (`@Valid` + Bean Validation), comprobación estricta de propiedad de objetos y configuración de esquema estricto en Jackson. Todas las mitigaciones fueron sometidas a retest manual (Postman) y pruebas unitarias automatizadas (`MockMvc`), alcanzando un **100% de efectividad en el bloqueo de vectores de ataque**.

---

## 2. Alcance (Scope)

La auditoría cubrió los siguientes componentes e interfaces del sistema:
- **Endpoints evaluados:**
  - `GET /api/usuarios`
  - `GET /api/usuarios/{id}`
  - `POST /api/usuarios`
  - `GET /api/pedidos`
  - `GET /api/pedidos/{id}`
  - `POST /api/pedidos`
- **Capas auditadas:** Controladores REST (`controller`), Entidades JPA (`model`), Capa de Servicios (`service`), Contratos de transferencia (`dto`), Configuración de deserialización Jackson y Manejo de Excepciones HTTP.
- **Entorno de pruebas:** Localhost (puerto `8080`), base de datos H2 en memoria con datos sembrados (usuarios Ana ID 1, Beto ID 2; pedidos 1, 2 y 3).

---

## 3. Metodología

La auditoría se ejecutó siguiendo las pautas de:
1. **OWASP API Security Top 10 (2023):** Referencial estándar de seguridad en APIs.
2. **Pruebas de Caja Gris:** Inspección estática de código fuente combinada con pruebas dinámicas de caja negra vía HTTP.
3. **Herramientas de Evaluación:**
   - **Postman:** Ejecución de colecciones estructuradas de explotación (`Coleccion_Explotacion_P1.json`) y validación (`Coleccion_Validacion_P1.json`).
   - **Spring Boot Test & MockMvc:** Suite de 9 pruebas de integración y seguridad automatizadas (`mvn test`).
   - **Inspección de Tráfico HTTP:** Análisis de cabeceras, códigos de estado y serialización JSON.

---

## 4. Inventario de Endpoints y Matriz de Riesgo

| Método | Endpoint | Parámetros / Headers | Función | Riesgo Inicial | Estado Final |
|---|---|---|---|---|---|
| `GET` | `/api/pedidos` | `X-User-Id` | Consulta de pedidos | BOLA (Filtro inexistente) | Seguro (Solo pedidos propios) |
| `GET` | `/api/pedidos/{id}` | `X-User-Id`, `id` en path | Detalle de pedido | BOLA + Fuga de contraseña | Seguro (403 en ajenos, sin password) |
| `POST` | `/api/pedidos` | `X-User-Id`, Body JSON | Registro de pedido | BOLA de escritura + Montos inválidos | Seguro (Dueño fijo por sesión, validado) |
| `GET` | `/api/usuarios` | Ninguno | Listado de usuarios | Exposición masiva de contraseñas | Seguro (DTO sin contraseña) |
| `GET` | `/api/usuarios/{id}` | `X-User-Id`, `id` en path | Consulta de usuario | BOLA + Exposición de contraseña | Seguro (Solo usuario propio, sin password) |
| `POST` | `/api/usuarios` | Body JSON | Registro de usuario | Mass Assignment (`rol: ADMIN`) | Seguro (Rol fijo USER, 400 en campos extra) |

---

## 5. Hallazgos Identificados

### Hallazgo 1: BOLA (Broken Object Level Authorization) — OWASP API1:2023
- **Severidad:** Crítica.
- **Mecanismo:** El endpoint `GET /api/pedidos/{id}` ignora la identidad del solicitante y retorna directamente la entidad asociada al ID numérico suministrado.
- **Riesgo:** Un atacante puede enumerar secuencias enteras de IDs (`1, 2, 3...`) extrayendo datos privados de todos los usuarios del sistema.

### Hallazgo 2: BOLA de Escritura en Creación de Transacciones — OWASP API1:2023
- **Severidad:** Alta.
- **Mecanismo:** `POST /api/pedidos` toma el campo `"usuario": {"id": X}` proporcionado en el JSON para persistir la clave foránea, omitiendo la verificación de quién es el emisor real de la petición.
- **Riesgo:** Fraude financiero, generación de cobros no autorizados y alteración malintencionada del historial de pedidos.

### Hallazgo 3: Asignación Masiva / BOPLA — OWASP API3:2023
- **Severidad:** Alta.
- **Mecanismo:** Mapeo directo entre el JSON entrante y la entidad `Usuario`. Se inyecta `"rol": "ADMIN"` durante el registro.
- **Riesgo:** Escalamiento a privilegios de superusuario en el sistema.

### Hallazgo 4: Divulgación Excesiva de Datos (Passwords) — OWASP API3:2023 / API8:2023
- **Severidad:** Crítica.
- **Mecanismo:** Ausencia de `@JsonIgnore` y falta de DTOs de salida. Las entidades son serializadas con su campo `password` intacto.
- **Riesgo:** Compromiso inmediato de todas las cuentas de usuario.

### Hallazgo 5: Ausencia de Validación de Esquema — OWASP API8:2023
- **Severidad:** Media.
- **Mecanismo:** No existe Bean Validation; se permiten montos negativos, montos ilimitados, textos vacíos y correos inválidos.

---

## 6. Plan de Remediación

Se definieron las siguientes medidas arquitectónicas:
1. **Control de Autorización a Nivel de Objeto:**
   - Creación de `UsuarioAutenticadoService` para resolución uniforme de la identidad.
   - En `PedidoService`, incorporar regla de negocio: si `pedido.getUsuario().getId() != usuario.getId()`, lanzar `AccesoDenegadoException` (mapeada a HTTP 403).
2. **Aislamiento de Modelos mediante DTOs:**
   - DTOs de entrada: `UsuarioRegistroDTO` (sin `rol`), `PedidoCreacionDTO` (sin `usuario`).
   - DTOs de salida: `UsuarioRespuestaDTO`, `PedidoRespuestaDTO` (sin credenciales).
3. **Endurecimiento de Deserialización:**
   - Activar `spring.jackson.deserialization.fail-on-unknown-properties=true` en `application.properties`.
4. **Validación de Datos:**
   - Agregar `spring-boot-starter-validation`, anotar DTOs con `@NotBlank`, `@Email`, `@Size`, `@Positive`, `@DecimalMax`.
5. **Manejo Uniforme de Excepciones:**
   - Configurar `GlobalExceptionHandler` con `@RestControllerAdvice` para estandarizar códigos 400, 401, 403 y 404, previniendo fuga de detalles de depuración.

---

## 7. Verificación y Retest (Pruebas Dinámicas)

Se ejecutó la colección Postman de validación sobre `http://localhost:8080`:

| Prueba | Petición Enviada | Cabecera | Resultado Esperado | Resultado Obtenido | Estatus |
|---|---|---|---|---|---|
| Retest BOLA Lectura | `GET /api/pedidos/3` | `X-User-Id: 1` | 403 Forbidden | **403 Forbidden** | **Superado** |
| Retest Sin Identidad | `GET /api/pedidos/1` | Ninguna | 401 Unauthorized | **401 Unauthorized** | **Superado** |
| Retest Usuario Ajeno | `GET /api/usuarios/2` | `X-User-Id: 1` | 403 Forbidden | **403 Forbidden** | **Superado** |
| Retest BOLA Escritura | `POST /api/pedidos` con `usuario: {id: 2}` | `X-User-Id: 1` | 400 Bad Request | **400 Bad Request** | **Superado** |
| Retest Mass Assignment | `POST /api/usuarios` con `"rol": "ADMIN"` | Ninguna | 400 Bad Request | **400 Bad Request** | **Superado** |
| Retest Email Inválido | `POST /api/usuarios` con email erróneo | Ninguna | 400 con mensaje | **400 Bad Request** | **Superado** |
| Retest Password Corto | `POST /api/usuarios` con clave < 8 chars | Ninguna | 400 con mensaje | **400 Bad Request** | **Superado** |

---

## 8. Pruebas Automatizadas de Seguridad

La suite de pruebas automatizadas con JUnit 5 y Spring MockMvc corrió exitosamente:

- **`PruebaBolaTest` (4 pruebas):**
  - `usuario1_obtieneSuPropioPedido_retorna200`: Pasa (200 OK).
  - `usuario1_solicitaPedidoDeBeto_retorna403`: Pasa (403 Forbidden).
  - `sinEncabezadoXUserId_retorna401`: Pasa (401 Unauthorized).
  - `usuario1_solicitaUsuarioAjeno_retorna403`: Pasa (403 Forbidden).
- **`PruebaMassAssignmentTest` (2 pruebas):**
  - `rolAdminEnJson_seIgnoraYSeAlmacenaUSER`: Pasa (201 Created con rol USER en persistencia).
  - `campoDesconocidoEnJson_retorna400`: Pasa (400 Bad Request por esquema estricto).
- **`PruebaValidacionTest` (3 pruebas):**
  - `emailInvalido_retorna400ConMensaje`: Pasa (400 Bad Request).
  - `passwordCorto_retorna400ConMensaje`: Pasa (400 Bad Request).
  - `nombreVacio_retorna400ConMensaje`: Pasa (400 Bad Request).

**Resultado Consolidado:** 9 pruebas ejecutadas, 0 fallos, 0 errores (**100% de éxito**).

---

## 9. Conclusiones y Recomendaciones

1. **Efectividad de las Medidas:** La introducción de DTOs y la verificación explícita de propiedad a nivel de servicio eliminó de raíz la vulnerabilidad BOLA y el escalamiento por Mass Assignment.
2. **Defensa en Profundidad:** Se combinó validación sintáctica (Bean Validation), semántica (lógica de negocio en servicio) y configuración de framework (`fail-on-unknown-properties`).
3. **Recomendación para Producción (Transición a P2):**
   - Sustituir la simulación de `X-User-Id` por tokens criptográficos robustos (JWT) validados mediante Spring Security.
   - Aplicar algoritmos de cifrado de un solo sentido (BCrypt o Argon2) para almacenamiento de contraseñas.
   - Implementar limitación de tasa (Rate Limiting) para mitigar intentos de fuerza bruta y enumeración masiva.

---

## 10. Anexos

- **Anexo A:** Colección Postman de Explotación: `codigo-original/pedidos-api-vulnerable/postman/Coleccion_Explotacion_P1.json`
- **Anexo B:** Colección Postman de Validación: `codigo-modificado/pedidos-api-seguro/postman/Coleccion_Validacion_P1.json`
- **Anexo C:** Código fuente de pruebas automatizadas: `codigo-modificado/pedidos-api-seguro/src/test/java/com/itson/ciberseguridad/seguridad/`

