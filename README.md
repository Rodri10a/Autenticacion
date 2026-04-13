# DevLearn Hub

Aplicacion web para gestionar topics de tecnologias de programacion con recursos y sistema de votaciones en tiempo real.

## Tech Stack

- **Node.js** + **Express** - Servidor web
- **PostgreSQL** + **pg** - Base de datos
- **EJS** - Motor de plantillas
- **Nodemon** - Recarga automatica en desarrollo

## Estructura del Proyecto

```
CRUD/
├── app.js                        # Punto de entrada del servidor
├── src/
│   ├── controllers/controller.js # Logica de negocio (CRUD + votos)
│   ├── models/
│   │   ├── db.js                 # Conexion a PostgreSQL
│   │   └── init.sql              # Schema y datos iniciales
│   ├── routes/routes.js          # Definicion de rutas
│   ├── views/
│   │   ├── index.ejs             # Vista principal
│   │   └── partials/             # Header y footer
│   └── public/
│       ├── css/style.css         # Estilos
│       └── js/main.js            # Votaciones con fetch
└── package.json
```

## Instalacion

1. Clonar el repositorio:

```bash
git clone <url-del-repo>
cd CRUD
```

2. Instalar dependencias:

```bash
npm install
```

3. Crear la base de datos en PostgreSQL:

```sql
CREATE DATABASE devlearn_hub;
```

4. Ejecutar el script de inicializacion:

```bash
psql -U postgres -d devlearn_hub -f src/models/init.sql
```

5. Configurar la conexion en `src/models/db.js` si es necesario (usuario, password, host, puerto).

6. Iniciar el servidor:

```bash
# Desarrollo (con recarga automatica)
npm run dev

# Produccion
npm start
```

La app estara disponible en `http://localhost:3000`.

## Base de Datos

Dos tablas con relacion uno a muchos:

**topics** - Tecnologias de programacion
| Campo       | Tipo         |
|-------------|--------------|
| id          | SERIAL PK    |
| title       | VARCHAR(255) |
| description | TEXT         |
| votes       | INTEGER      |

**links** - Recursos asociados a cada topic
| Campo    | Tipo         |
|----------|--------------|
| id       | SERIAL PK    |
| topic_id | FK → topics  |
| title    | VARCHAR(255) |
| url      | TEXT         |
| votes    | INTEGER      |

## Rutas

### Topics
| Metodo | Ruta                  | Accion              |
|--------|-----------------------|----------------------|
| GET    | `/`                   | Listar todos         |
| POST   | `/topics`             | Crear topic          |
| POST   | `/topics/:id/update`  | Actualizar topic     |
| POST   | `/topics/:id/delete`  | Eliminar topic       |
| POST   | `/topics/:id/vote`    | Votar (AJAX → JSON)  |

### Links
| Metodo | Ruta                                | Accion              |
|--------|-------------------------------------|----------------------|
| POST   | `/topics/:id/links`                 | Agregar link         |
| POST   | `/topics/:id/links/:linkId/update`  | Actualizar link      |
| POST   | `/topics/:id/links/:linkId/delete`  | Eliminar link        |
| POST   | `/topics/:id/links/:linkId/vote`    | Votar (AJAX → JSON)  |

## Funcionalidades

- **CRUD completo** de topics y links con formularios inline
- **Votaciones en tiempo real** sin recargar la pagina (fetch + JSON)
- **Interfaz responsiva** con cards, navbar y botones con colores por accion
- **Eliminacion en cascada** - al borrar un topic se borran sus links
