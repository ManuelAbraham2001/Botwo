# Botwo 🤖

## Descripción General
Botwo es un bot de WhatsApp diseñado para simplificar tareas de Google Workspace. Utilizando tecnologías avanzadas como Gemini y function calling, Botwo permite interactuar fácilmente con diversos servicios de Google directamente desde WhatsApp.

---

## 🛠 Tecnologías

**Backend**:  
- Node.js  
- Express  

**Servicios en la Nube**:  
- Twilio (Integración de WhatsApp)  
- Cloud SQL (MySQL)  
- Cloud Run (Despliegue)  

**Autenticación**: OAuth2  

**APIs de Google**:  
- Meet  
- Drive  
- Translate  
- Gemini  
- Vertex AI  
- Gmail  
- Calendar  
- Cloud Vision  

---

## 🔒 Seguridad
Botwo garantiza una seguridad robusta mediante múltiples capas:  
- Autenticación OAuth2  
- Almacenamiento de refresh tokens encriptados con bcrypt  
- Validación de tokens en cada llamada de función  
- Verificación de mensajes exclusivamente desde WhatsApp  

---

## 📅 Funcionalidades

### **Calendario**
#### Crear Evento  
**Comando**: `createEvent`  
**Parámetros**:  
- `summary`: Asunto del evento  
- `location` (opcional): Ubicación  
- `description` (opcional): Descripción  
- `startDateTime`: Fecha y hora de inicio  
- `endDateTime`: Fecha y hora de finalización  
- `timeZone` (opcional): Zona horaria  
- `attendees` (opcional): Lista de correos de participantes  

**Ejemplo de Prompt**:  
> Crea una reunión el lunes 9 de diciembre de 15 a 16hs argentina, con el asunto reunión importante  

---

#### Listar Eventos  
**Comando**: `listEvents`  
**Descripción**: Lista los 10 próximos eventos del calendario de Google  

**Ejemplo de Prompt**:  
> Lista los próximos eventos del calendario  

---

#### Modificar Evento  
**Comando**: `modifyEvent`  
**Parámetros**:  
- `eventName`: Nombre del evento  
- `eventDate`: Fecha del evento  
- `updatedFields` (opcional): Campos a actualizar  
- `participants` (opcional): Nuevos participantes  
- `removeParticipants` (opcional): Participantes a eliminar  

**Ejemplo de Prompt**:  
> Modifica la reunión del lunes 9 de diciembre, invita a usuario@gmail.com, cámbiale el asunto a reunión importante con usuario y establece el horario de 15 a 16 hora argentina.  

---

#### Verificar Disponibilidad  
**Comando**: `checkAvailability`  
**Parámetros**:  
- `email`: Correo del usuario  
- `startDate`: Fecha a verificar  

**Ejemplo de Prompt**:  
> Dime la disponibilidad de usuario@gmail.com para el lunes 9 de diciembre  

---

#### Cancelar Evento  
**Comando**: `cancelEvent`  
**Parámetros**:  
- `eventName`: Nombre del evento  
- `eventDate`: Fecha del evento  

**Ejemplo de Prompt**:  
> Elimina la reunión importante del lunes 9 de diciembre  

---

### **Drive**
#### Subir Archivo  
**Comando**: `uploadToDrive`  
**Parámetros**:  
- `url`: URL del archivo  
- `filename` (opcional): Nombre del archivo  

**Ejemplo de Prompt**:  
> Sube este archivo a drive  

---

#### Buscar Archivo  
**Comando**: `searchInDrive`  
**Parámetros**:  
- `token`: Token de autenticación  
- `searchTerm`: Término de búsqueda  

**Ejemplo de Prompt**:  
> Busca en drive el archivo instructivo_botwo  

---

#### Eliminar Archivo  
**Comando**: `searchInDrive`  
**Parámetros**:  
- `token`: Token de autenticación  
- `searchTerm`: Término de búsqueda  

**Ejemplo de Prompt**:  
> Elimina de drive el archivo instructivo_botwo  

---

### **Meet**
#### Crear Meet  
**Comando**: `createMeet`  
**Descripción**: Crea una reunión de Google Meet y devuelve la URL de acceso  

**Ejemplo de Prompt**:  
> Crea un meet  

---

### **Gmail**
#### Enviar Email  
**Comando**: `sendEmail`  
**Parámetros**:  
- `addressees`: Lista de correos destinatarios  
- `subject`: Asunto del correo  
- `text`: Contenido del correo  

**Ejemplo de Prompt**:  
> Manda un email a usuario@gmail.com con el asunto información solicitada que diga acá está la información que me solicitaste  

---

#### Listar Emails No Leídos  
**Comando**: `listUnread`  
**Descripción**: Muestra los últimos 10 emails sin leer  

**Ejemplo de Prompt**:  
> Muéstrame los últimos mails no leídos  

---

#### Buscar Emails  
**Comando**: `searchEmail`  
**Parámetros**:  
- `searchTerm`: Término de búsqueda  

**Ejemplo de Prompt**:  
> Busca mails con el asunto Bienvenido Botwo  

---

#### Marcar Todos los Emails como Leídos  
**Comando**: `marksAllEmailsAsRead`  
**Descripción**: Marca todos los emails como leídos en segundo plano  

**Ejemplo de Prompt**:  
> Marca todos los mails como leídos  

---

### **Fotos**
#### Extraer Texto de Imágenes  
**Comando**: `extractTextFromPhoto`  
**Parámetros**:  
- `url`: URL de la imagen  

**Ejemplo de Prompt**:  
> Extrae el texto de esta imagen (adjunto)  

---

## 🚨 Limitaciones
- Botwo no mantiene contexto de conversación  
- Cada comando debe ser específico y completo  

---

## 🚀 Cómo Probar
1. Envía un mensaje a `+14155238886` en WhatsApp  
2. Escribe `"join swept-round"`  
3. Sigue las instrucciones de autenticación  

**Enlace directo**: [Unirse a Botwo](#)

---

## 📝 Nota
Botwo está en etapa de prueba. ¡Disfruta tus automatizaciones!
