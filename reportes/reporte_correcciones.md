# Reporte de Correcciones y Mitigaciones — Práctica 1

**Institución:** Instituto Tecnológico de Sonora (ITSON)  
**Materia:** Ciberseguridad Aplicada · Ingeniería en Software  
**Proyecto:** `pedidos-api-seguro`  
**Fecha:** Noviembre 2026  

---

## 1. Matriz de Correcciones Aplicadas

| ID Hallazgo | Vulnerabilidad Original | Archivos Modificados / Creados | Control Implementado | Resultado del Retest | Estado |
|---|---|---|---|---|---|
| **P1-001** | BOLA en `GET /api/pedidos/{id}` | `PedidoController.java`<br>`PedidoService.java`<br>`UsuarioAutenticadoService.java` | Verificación de propiedad del recurso (`pedido.usuario.id == usuarioAutenticado.id`). Retorno de `403 Forbidden` si es ajeno, o `401 Unauthorized` si no hay sesión. | Retorna **403 Forbidden** con mensaje *"No tiene permisos para acceder al pedido solicitado"*. | **Corregido / Verificado** |
| **P1-002** | BOLA de escritura en `POST /api/pedidos` | `PedidoCreacionDTO.java`<br>`PedidoController.java`<br>`PedidoService.java` | Desacoplamiento de entidad. El DTO de entrada no expone `usuario`; el propietario se asigna estrictamente en el backend desde `X-User-Id`. | Si se envía `usuario: {id: 2}`, Jackson lo rechaza con **400 Bad Request**; de lo contrario se asocia al usuario autenticado. | **Corregido / Verificado** |
| **P1-003** | Mass Assignment en `POST /api/usuarios` | `UsuarioRegistroDTO.java`<br>`UsuarioController.java`<br>`application.properties` | El DTO de entrada solo contiene `nombre`, `email`, `password`. El servidor asigna rol inmutable `"USER"`. Se activa `fail-on-unknown-properties=true`. | El campo `rol` es ignorado o rechazado con **400 Bad Request**. Nunca se crea un `ADMIN`. | **Corregido / Verificado** |
| **P1-004** | Exposición de credenciales | `Usuario.java`<br>`UsuarioRespuestaDTO.java`<br>`PedidoRespuestaDTO.java` | `@JsonIgnore` en `Usuario.password` y uso estricto de DTOs de salida (`UsuarioRespuestaDTO` y `PedidoRespuestaDTO`). | Las contraseñas quedan omitidas del 100% de los endpoints. | **Corregido / Verificado** |
| **P1-005** | Validación deficiente de esquemas | `pom.xml`<br>`UsuarioRegistroDTO.java`<br>`PedidoCreacionDTO.java`<br>`GlobalExceptionHandler.java` | Inclusión de `spring-boot-starter-validation`, uso de `@Valid`, `@NotBlank`, `@Email`, `@Size`, `@Positive`, `@DecimalMax` y manejador de errores limpio. | Peticiones inválidas devuelven **400 Bad Request** con mapa detallado de campos con error. | **Corregido / Verificado** |

---

## 2. Detalle Técnico de los Cambios Implementados

### 2.1 Mitigación de BOLA (API1:2023)
- **Implementación en `PedidoController.java`:**
  ```java
  @GetMapping("/{id}")
  public ResponseEntity<PedidoRespuestaDTO> obtenerPorId(
          @PathVariable Long id,
          @RequestHeader(value = "X-User-Id", required = false) String encabezadoXUserId) {
      Usuario usuario = usuarioAutenticadoService.obtenerUsuarioAutenticado(encabezadoXUserId);
      Pedido pedido = pedidoService.obtenerDelUsuario(id, usuario);
      return ResponseEntity.ok(pedidoService.aRespuestaDTO(pedido));
  }
  ```
- **Lógica de autorización en `PedidoService.java`:**
  ```java
  public Pedido obtenerDelUsuario(Long idPedido, Usuario usuario) {
      Pedido pedido = pedidoRepository.findById(idPedido)
              .orElseThrow(() -> new RecursoNoEncontradoException("Pedido no encontrado: " + idPedido));
      if (!pedido.getUsuario().getId().equals(usuario.getId())) {
          throw new AccesoDenegadoException("No tiene permisos para acceder al pedido solicitado");
      }
      return pedido;
  }
  ```
- **Evidencia del Retest (Postman / MockMvc):**
  - Petición: `GET /api/pedidos/3` con cabecera `X-User-Id: 1`
  - Código obtenido: **403 Forbidden**
  - Cuerpo:
    ```json
    {
      "codigo": 403,
      "error": "No tiene permisos para acceder al pedido solicitado",
      "timestamp": "2026-11-19T22:15:00"
    }
    ```

---

### 2.2 Mitigación de BOLA de Escritura (API1:2023)
- **Implementación en `PedidoCreacionDTO.java`:**
  El DTO define únicamente campos de negocio, sin referencias a identidades:
  ```java
  public class PedidoCreacionDTO {
      @NotBlank(message = "La descripción es obligatoria")
      private String descripcion;

      @Positive(message = "El monto debe ser mayor a cero")
      @DecimalMax(value = "50000.00", message = "El monto máximo permitido es $50,000.00")
      private double monto;
      // No contiene atributo Usuario ni usuarioId
  }
  ```
- En `PedidoService.crear(dto, usuario)`, el objeto `Pedido` se enlaza forzosamente con la instancia de `usuario` recuperada de la sesión.

---

### 2.3 Mitigación de Mass Assignment y Esquema Estricto (API3:2023)
- **Implementación en `UsuarioRegistroDTO.java`:**
  Contrato que limita los atributos que el cliente puede proveer:
  ```java
  public class UsuarioRegistroDTO {
      @NotBlank(message = "El nombre es obligatorio")
      private String nombre;

      @NotBlank(message = "El correo electrónico es obligatorio")
      @Email(message = "El correo electrónico no tiene un formato válido")
      private String email;

      @NotBlank(message = "La contraseña es obligatoria")
      @Size(min = 8, max = 64, message = "La contraseña debe tener entre 8 y 64 caracteres")
      private String password;
      // rol e id no existen en el contrato de entrada
  }
  ```
- **Configuración estricta en `application.properties`:**
  ```properties
  spring.jackson.deserialization.fail-on-unknown-properties=true
  ```
- **Evidencia del Retest:**
  - Envío de payload con `"rol": "ADMIN"` o `"esAdmin": true`.
  - Código obtenido: **400 Bad Request**.
  - Si el campo es procesado sin unknown-properties, el backend asigna inmutablemente: `nuevo.setRol("USER")`.

---

### 2.4 Mitigación de Exposición de Datos Sensibles
- **Implementación en `Usuario.java`:**
  ```java
  @JsonIgnore
  private String password;
  ```
- **DTOs de Salida:**
  - `UsuarioRespuestaDTO`: solo transmite `id`, `nombre`, `email`, `rol`.
  - `PedidoRespuestaDTO`: solo transmite `id`, `descripcion`, `monto`, `fecha`, `idUsuario`, `nombreUsuario`.
- **Evidencia del Retest:**
  - Consulta `GET /api/usuarios` o `GET /api/pedidos/1`.
  - En ningún JSON se encuentra la clave `"password"`.

---

### 2.5 Validación de Esquemas y Manejo Centralizado de Errores (API8:2023)
- **Manejador Global (`GlobalExceptionHandler.java`):**
  Intercepta `MethodArgumentNotValidException`, mapea los nombres de campo con sus mensajes de error de Bean Validation y retorna un `400 Bad Request` legible y sin trazas de pila (stack traces).
- **Evidencia del Retest:**
  - Envío de `{ "nombre": "", "email": "correo-invalido", "password": "123" }`
  - Código obtenido: **400 Bad Request**
  - Cuerpo:
    ```json
    {
      "nombre": "El nombre es obligatorio",
      "email": "El correo electrónico no tiene un formato válido",
      "password": "La contraseña debe tener entre 8 y 64 caracteres"
    }
    ```

---

## 3. Verificación de Pruebas Automatizadas

Se ejecutó la suite de pruebas automatizadas mediante `mvn test`:

```
[INFO] Running com.itson.ciberseguridad.seguridad.PruebaBolaTest
[INFO] Tests run: 4, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 1.842 s
[INFO] Running com.itson.ciberseguridad.seguridad.PruebaMassAssignmentTest
[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.312 s
[INFO] Running com.itson.ciberseguridad.seguridad.PruebaValidacionTest
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.285 s
[INFO] 
[INFO] Results:
[INFO] 
[INFO] Tests run: 9, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

Todas las defensas han quedado verificadas y operacionales.

