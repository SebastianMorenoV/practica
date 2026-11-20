# Práctica 1 — Seguridad en APIs

**Materia:** Ciberseguridad Aplicada · Ingeniería en Software  
**Institución:** Instituto Tecnológico de Sonora (ITSON)  
**Unidad de Competencia:** UC3 — Seguridad de APIs y DevSecOps  

---

## 👥 Integrantes del Equipo

- Sebastián Moreno (y compañeros de equipo)

---

## 📁 Estructura del Repositorio

El repositorio está organizado conforme a los requerimientos de entrega de la práctica:

```
practica/
├── codigo-original/
│   └── pedidos-api-vulnerable/      # API Spring Boot con fallas de seguridad intencionales
│       └── postman/
│           └── Coleccion_Explotacion_P1.json
├── codigo-modificado/
│   └── pedidos-api-seguro/          # API Spring Boot corregida con DTOs, @Valid y control anti-BOLA
│       ├── postman/
│           └── Coleccion_Validacion_P1.json
│       └── src/test/java/com/itson/ciberseguridad/seguridad/  # Pruebas automatizadas de seguridad
├── reportes/
│   ├── reporte_vulnerabilidades.md  # Detalle de hallazgos (BOLA, Mass Assignment, Exposición de Datos)
│   ├── reporte_correcciones.md      # Matriz de cambios técnicos, archivos y evidencias de retest
│   └── reporte_auditoria.md         # Informe formal de auditoría estructurado en 10 secciones
├── evidencias/
│   └── guia_evidencias_postman.md   # Registro completo de peticiones y respuestas HTTP
├── INSTRUCCIONES_P1.md              # Documentación detallada original de la práctica
└── README.md                        # Guía principal del repositorio
```

---

## 🎯 Objetivos de la Práctica

1. **Identificar y explotar BOLA (Broken Object Level Authorization - OWASP API1:2023):** Acceder y crear pedidos ajenos manipulando IDs en URLs y cuerpos JSON.
2. **Identificar y explotar Mass Assignment / BOPLA (OWASP API3:2023):** Autoasignarse rol de `ADMIN` al registrarse aprovechando el binding directo a entidades.
3. **Verificar exposición excesiva de datos:** Detección de contraseñas transmitidas en texto claro en los payloads de respuesta.
4. **Implementar mitigaciones seguras:** Uso de DTOs, Bean Validation (`@Valid`), comprobación de pertenencia en servicios, `@JsonIgnore` y esquemas estrictos de Jackson (`fail-on-unknown-properties=true`).
5. **Automatización:** Ejecución de suite de pruebas de seguridad con Spring MockMvc (`mvn test`).

---

## 🚀 Instrucciones de Ejecución

### Opción 1: Ejecución desde NetBeans

1. **Abrir el proyecto vulnerable:**
   - En Apache NetBeans: `File > Open Project...`
   - Seleccionar `codigo-original/pedidos-api-vulnerable`.
   - Clic derecho sobre el proyecto → **Run**.
   - La API arrancará en `http://localhost:8080`.
2. **Realizar los ataques con Postman:**
   - Importar la colección: `codigo-original/pedidos-api-vulnerable/postman/Coleccion_Explotacion_P1.json`.
   - Ejecutar las peticiones en orden y capturar las respuestas vulnerables (códigos 200/201).
3. **Detener la API vulnerable:**
   - Clic en el botón rojo de detener en NetBeans.
4. **Abrir y ejecutar la versión segura:**
   - Abrir `codigo-modificado/pedidos-api-seguro`.
   - Clic derecho sobre el proyecto → **Run**.
5. **Validar las defensas con Postman:**
   - Importar: `codigo-modificado/pedidos-api-seguro/postman/Coleccion_Validacion_P1.json`.
   - Verificar que los ataques son bloqueados con `403 Forbidden`, `401 Unauthorized` y `400 Bad Request`.
6. **Correr las pruebas automatizadas de seguridad:**
   - Clic derecho sobre `pedidos-api-seguro` → **Test Project** (o `Alt + F6`).

---

### Opción 2: Ejecución desde Terminal / Codespaces

1. **Iniciar la API vulnerable:**
   ```bash
   cd codigo-original/pedidos-api-vulnerable
   mvn spring-boot:run
   ```
2. **Detener (Ctrl + C) y correr la versión segura:**
   ```bash
   cd ../../codigo-modificado/pedidos-api-seguro
   mvn spring-boot:run
   ```
3. **Ejecutar las pruebas automatizadas de seguridad:**
   ```bash
   cd codigo-modificado/pedidos-api-seguro
   mvn test
   ```

---

## 📊 Resumen de Hallazgos y Remediaciones

| Hallazgo | Categoría OWASP | Comportamiento Vulnerable | Solución Segura |
|---|---|---|---|
| **BOLA de lectura** | API1:2023 | Cualquier usuario con `X-User-Id` consulta pedidos ajenos en `GET /api/pedidos/{id}` | Se valida propiedad con `pedido.usuario.id == usuarioAutenticado.id`; si no coincide, devuelve **403 Forbidden**. |
| **BOLA de escritura** | API1:2023 | En `POST /api/pedidos` se inyecta `"usuario": {"id": 2}` en el JSON para cargar pedidos a otros | Se utiliza `PedidoCreacionDTO` sin campo de usuario; el dueño se extrae obligatoriamente del contexto autenticado. |
| **Mass Assignment** | API3:2023 | En `POST /api/usuarios` se envía `"rol": "ADMIN"` y se guarda como administrador | Se utiliza `UsuarioRegistroDTO` sin atributo `rol`. El backend fija `"USER"` y el esquema estricto de Jackson rechaza propiedades desconocidas (**400 Bad Request**). |
| **Exposición de contraseñas** | API3 / API8:2023 | `GET /api/usuarios` y `GET /api/pedidos/{id}` exponen la contraseña en texto claro | Se añade `@JsonIgnore` en `password` y se devuelven exclusivamente DTOs de salida (`UsuarioRespuestaDTO`, `PedidoRespuestaDTO`). |
| **Falta de validación** | API8:2023 | Se aceptan montos negativos, emails mal formados y contraseñas débiles | Inclusión de `spring-boot-starter-validation`, `@Valid` en controladores y mensajes amigables centralizados en `GlobalExceptionHandler`. |

---

## 📑 Reportes Generados

- [Reporte de Vulnerabilidades](file:///c:/Users/moren/Documents/GitHub/practica/reportes/reporte_vulnerabilidades.md)
- [Reporte de Correcciones](file:///c:/Users/moren/Documents/GitHub/practica/reportes/reporte_correcciones.md)
- [Reporte de Auditoría (10 Secciones)](file:///c:/Users/moren/Documents/GitHub/practica/reportes/reporte_auditoria.md)
- [Guía de Evidencias Postman / cURL](file:///c:/Users/moren/Documents/GitHub/practica/evidencias/guia_evidencias_postman.md)
