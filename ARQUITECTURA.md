# Uise — Arquitectura y Alcance

> Infraestructura de protocolo para la economía de agentes de IA autónomos.
> Estado: **decisiones de diseño cerradas, pre-implementación.**
> Fecha: 2026-08-09

---

## 0. Posicionamiento: la prueba, no el riel de pagos

**Uise es la prueba de lo que hicieron los agentes.**

Un agente compra, negocia, entrega, gasta. Cuando algo sale mal —la cantidad equivocada, un precio
que nadie acordó, trabajo que una parte dice que nunca se entregó— hoy **no existe ninguna
evidencia**. Solo un archivo de registro que cualquiera de las dos partes puede editar.

Ninguna empresa seria va a dar poder de gasto a mil agentes sin poder demostrar qué hicieron.

| | Riel de pagos | **Sistema de prueba** |
|---|---|---|
| Competencia | Stripe, Coinbase, Google | Casi nadie |
| Precio por unidad | Céntimos de céntimo | Presupuestos de cumplimiento |
| Regulación | Licencias país por país | Ninguna |
| Quién empuja la adopción | Tú, convenciendo | Auditores, aseguradoras, reguladores |
| Primer cliente | Dos agentes que ya se paguen | Una empresa con agentes y un auditor |
| ¿Se copia? | Sí, en meses | **No: el valor es el historial acumulado** |

Esa última fila es la decisiva. Un riel de pagos se replica. **Un registro de años de evidencia
verificable no se replica jamás** — quien empiece mañana empieza vacío. El tiempo trabaja a favor.

Y elimina el problema del huevo y la gallina: como riel de pagos no sirves hasta que dos agentes se
paguen entre sí; como sistema de prueba **sirves con un solo cliente y sus propios agentes**, aunque
no se mueva dinero. Un recibo con `amount: "0"` es prueba pura: *esto se pidió, esto se entregó,
ambas partes firmaron.*

Los pagos llegan después, encima de un registro que ya nadie discute.

**Esto no cambió el código.** Lo construido sirve igual; apunta a otro sitio.

---

## 1. Decisión fundamental: dos planos separados

Uise NO transporta la conversación entre agentes. Uise transporta y certifica **el valor**.

| | Plano de conversación | Plano de valor |
|---|---|---|
| Contenido | Agentes negociando, coordinando, ejecutando | "El trabajo se hizo. Se deben $X de A a B." |
| Volumen esperado | Trillones/día | ~0.1% del anterior |
| Ruta | Directo agente↔agente (P2P), sobre firmado | Obligatoriamente por un nodo Uise |
| Infraestructura de Uise en el camino | Ninguna (relay opcional si el agente no tiene IP pública) | Sí, obligatoria |
| Costo operativo para Uise | Cero | Bajo |
| Modelo de ingreso | Ninguno, y así debe ser | Fee por transacción |
| Escala requerida | Ilimitada | ~65,000 tx/s (escala Visa) |

### Por qué (la lección de Visa)

La red completa de VisaNet opera en el orden de **65,000 transacciones por segundo**. Con eso mueve
~$15 billones al año y sostiene una empresa de ~$600 mil millones. Visa nunca ve el producto, ni la
negociación, ni la entrega: solo ve un mensaje diminuto de autorización y liquidación.

Consecuencias directas:

1. **Cobrar por mensaje es competir contra HTTP**, cuyo costo marginal es cero. Se pierde siempre.
2. **Cobrar por transacción es competir contra Visa al ~2%.** Ahí está el valor.
3. Transportar trillones de mensajes de chatter convierte a Uise en un centro de costo tipo AWS,
   con los costos de AWS y sin sus márgenes.

### Por qué esto permite "trillones de agentes"

"Trillones de agentes" no es un requisito de throughput: es un **requisito de topología**.

> Si existe cualquier componente global en el camino crítico de la conversación (registro central,
> contador global, ledger único, gateway propio), el número máximo de agentes no es trillones —
> es lo que aguante ese componente.

HTTP escala a toda la web porque no tiene servidor central. El plano de conversación de Uise es P2P
por la misma razón. El plano de valor sí puede tener componentes centrales, porque su volumen es
órdenes de magnitud menor.

### De dónde viene la defensibilidad

No del código: un gateway se reescribe en un fin de semana. Viene de cuatro cosas:

1. **El spec** — público, fechado, licencia Apache 2.0 con patent grant.
2. **La suite de conformidad** — quien no la pasa, no es Uise.
3. **El recibo firmado** — Uise es el único emisor de la prueba que ambas partes aceptan.
4. **Adopción.**

### Modelo decidido: protocolo abierto, liquidación cerrada

| Componente | Licencia | Razón |
|---|---|---|
| `spec/` | Apache 2.0 + patent grant | Un protocolo cerrado no se vuelve estándar. La publicación fechada y pública *es* la prueba de autoría. |
| `conformance/` | Apache 2.0 | Define qué es Uise. Debe ser verificable por cualquiera. |
| `reference/uise-py/` (SDK) | Apache 2.0 | Sin SDK libre no hay integración. |
| `node/` — discovery y relay | Apache 2.0 | Que cualquiera pueda correr uno; refuerza la topología P2P. |
| **Nodo de liquidación / emisión de recibos** | **Cerrado** | Es el negocio. Uise es el emisor del recibo que ambas partes aceptan, igual que Visa es el emisor de la autorización. |

Es el modelo exacto de TCP/IP (protocolo abierto, nadie compite con él) combinado con el de Visa
(reglas públicas, liquidación propietaria).

---

## 2. UIP-1 — las cinco primitivas

Ni una más en v0.1.

| # | Primitiva | Definición | Congelado para siempre |
|---|---|---|---|
| 1 | **Identidad** | `did:key` + Ed25519. Un agente *es* su llave pública. Verificable offline, sin red, sin registro, sin consenso. | Sí |
| 2 | **Envelope** | Sobre firmado. Campos: `v, id, from, to, type, ts, ttl, nonce, body_hash, sig`. | **Sí — irreversible** |
| 3 | **Capability Descriptor** | Cómo un agente declara qué sabe hacer, legible por otro agente sin humano. Adaptadores a MCP tools y A2A AgentCard. | Extensible |
| 4 | **Transport binding** | HTTP/1.1 + SSE primero. gRPC y NATS como bindings alternos del *mismo* sobre. | Extensible |
| 5 | **Receipt** | Recibo firmado: quién pidió, quién ejecutó, qué se entregó, qué se debe, en qué unidad. | **Sí — irreversible** |

**El #5 es la jugada estratégica.** Ni A2A (Google) ni MCP (Anthropic) llevan liquidación en el
protocolo. Si el recibo está en el núcleo del sobre desde v1, Uise es el único protocolo donde el
valor es nativo. Si no está en v1, no se puede añadir después sin romper la red entera.

---

## 2.1 Seguridad post-cuántica

Un computador cuántico rompe Ed25519. Eso no afecta igual a las dos mitades del sistema:

| | Un mensaje | **Un recibo** |
|---|---|---|
| Cuánto debe resistir | 24 h (`ttl`) | **Décadas** |
| Si el algoritmo cae en 2040 | Nada: ya caducó | **Se pueden falsificar recibos de 2026 hacia atrás** |
| Urgencia post-cuántica | Migrar antes de que existan los cuánticos | **Hoy** |

Un recibo es prueba legal permanente. Un algoritmo roto en 2040 no solo deja de funcionar: destruye
retroactivamente todos los recibos emitidos bajo él. De ahí las cuatro decisiones:

1. **El sobre nunca nombra un algoritmo.** Lo declara el multicodec dentro del DID del emisor.
   Añadir un algoritmo post-cuántico añade una entrada al registro y un DID nuevo — **nunca una
   versión nueva del protocolo**. Esta es la propiedad de longevidad más importante del diseño.
2. **El campo `sig` no tiene longitud fija.** Ed25519 son 64 bytes; una firma híbrida post-cuántica,
   varios miles. Un verificador que fije 64 no puede hablar con un agente post-cuántico.
3. **Los emisores firman híbrido** (clásico + ML-DSA). Doble candado: protege contra un ataque
   cuántico al componente clásico y contra un fallo aún no descubierto en el algoritmo nuevo.
4. **Registro público de solo-añadir** (árbol Merkle, construcción de RFC 6962). Las pruebas Merkle
   se apoyan solo en hashes, que resisten a los cuánticos. Un recibo cuya firma se rompa en 2040
   conserva prueba verificable de que existió sin modificarse. Además, elimina la necesidad de
   confiar en Uise: cualquiera audita que nunca emitió un recibo falso ni borró uno.

**Sin criptografía casera.** Implementar ML-DSA a mano sería exactamente la tecnología rota que hay
que evitar: la criptografía de retículos falla en silencio. El protocolo queda agnóstico al
algoritmo; la implementación usa librerías auditadas. Y **ningún codepoint multicodec se inventa**:
usar un identificador no asignado fragmentaría el espacio de nombres para siempre.

---

## 3. Decisiones técnicas cerradas

| Decisión | Elección | Razón |
|---|---|---|
| Wire format | Sobre UIP propio + adaptadores MCP/A2A | El recibo debe estar en el núcleo; ninguno de los dos lo tiene |
| Identidad | `did:key` Ed25519 | Cero dependencias, cero red, cero blockchain |
| Encoding del sobre firmado | **JSON canónico (JCS, RFC 8785)** | Firmar exige bytes canónicos. MessagePack no tiene forma canónica estándar: dos implementaciones producirían firmas que no validan entre sí. Fallo permanente e invisible. |
| Payload | Opaco, con `content-type` declarado | Uise no interpreta el contenido |
| Compresión | Opcional, a nivel de transporte | zlib en mensajes <1KB añade latencia y casi no comprime |
| Persistencia y colas | **NATS JetStream + PostgreSQL** | JetStream cubre colas, QoS, streams, KV y discovery: reemplaza Redis *y* etcd |
| Lenguaje | Python (spec, referencia, SDK) → Rust (nodo de liquidación cuando llegue volumen) | A escala Visa el plano de valor cabe en pocos nodos; el chatter ya no pasa por Uise |
| Licencia | Apache 2.0 + patent grant | Adopción es el foso; el control está en la conformidad y el recibo |

### Identidad: la separación que faltaba en el plan original

| | Qué es | Cuándo |
|---|---|---|
| Identidad **criptográfica** | `did:key` + firma en cada sobre | **Ahora — es parte del protocolo** |
| Identidad **registrada** | Registro on-chain, reputación, ZK proofs, sandbox verificable | Después — infraestructura separada |

Es el modelo de TLS: la criptografía del handshake *es* el protocolo; el PKI y las CAs llegaron
después y se pueden cambiar sin romper nada.

---

## 3.1 El nodo y el registro público

El nodo hace exactamente tres cosas, y ninguna es transportar conversaciones:

1. **Descubrimiento** — acepta anuncios firmados y responde consultas por capacidad. Gratis,
   de solo lectura, y cualquiera puede correr uno.
2. **Emisión** — verifica lo que dos partes ya acordaron, añade la tercera firma, y **cobra por
   ese acto**. Este es el negocio.
3. **Transparencia** — publica cada recibo en un árbol Merkle de solo-añadir (RFC 6962) con una
   cabeza de árbol firmada.

**Por qué el registro público es la pieza que te hace el emisor aceptado:** un auditor fija una
cabeza de árbol, vuelve más tarde, pide una prueba de consistencia, y demuestra que nada se
reescribió ni se borró en medio — usando solo una función hash. El mal comportamiento se vuelve
**detectable**, no simplemente prohibido. Nadie tiene que confiar en ti; se comprueba.

Y como es hash puro, esa prueba sigue funcionando después de que se rompa cualquier algoritmo de
firma que se use hoy.

**El fee se cobra por emitir la prueba, nunca por mover dinero.** El nodo nunca sostiene ni
transfiere fondos: es un servicio de datos, no un transmisor de fondos regulado.

---

## 3.2 El dinero: dos flujos que nunca se mezclan

| | **El dinero de Uise** | **El dinero entre agentes** |
|---|---|---|
| Qué es | Tu comisión por emitir el recibo | Lo que un agente le debe a otro |
| Quién paga | Tu cliente, a ti | Un agente a otro |
| Qué eres | Un proveedor de software cobrando su servicio | Un **intermediario financiero** |
| Licencias | Ninguna | Transmisor de fondos, país por país |
| El nodo lo toca | Sí, es su factura | **Nunca** |

Confundirlos es lo que convierte una empresa de protocolo en un banco sin licencia. El nodo
**registra la obligación y jamás sostiene el dinero de otros.**

**Quién paga la comisión:** por defecto, el `payee` — el que cobra. Es el modelo de las redes de
tarjetas: el comercio paga el interchange, porque la prueba es la que lo protege.

**Rieles de cobro:** `manual` (facturas y transferencia, funciona desde el día uno), `stripe`
(tarjeta, débito, ACH/SEPA → tu cuenta bancaria) y `stablecoin` (USDC → tu wallet). Los tres detrás
de una misma interfaz, sin lock-in.

**Ningún riel ejecuta nada.** Preparan la petición de cobro y se detienen; la envía tu propio código
con tus propias claves. Y **no hay ningún botón de retirar dinero** en este software: los payouts se
hacen en la consola de tu proveedor, donde ya viven tus credenciales y sus controles antifraude. Un
flujo de retiro aquí significaría custodiar fondos — justo lo que toda la arquitectura evita.

**Dos superficies HTTP que nunca se mezclan:** `/uip/v1/*` es el protocolo — abierto y congelado,
lo implementa cualquiera. `/api/v1/*` es el producto de Uise — con token, y puede evolucionar. Si se
mezclan, tu API comercial se vuelve parte del estándar y ya no la puedes cambiar. El spec reserva el
prefijo `/uip/v1` de forma normativa.

**La consola** (`/dashboard`) es **un cliente de la API pública, no una puerta trasera**: lee
`/api/v1/stats` y se suscribe a `/api/v1/events` igual que lo haría la herramienta de un cliente. Si
la consola necesitara algo que la API no da, la API estaría incompleta y todos tus clientes
chocarían con el mismo muro.

Se renderiza primero en el servidor y se actualiza después en vivo: las cifras son correctas en el
instante en que carga, y siguen siéndolo —congeladas— si el navegador no ejecuta scripts. Una
consola que no muestra nada hasta que el JavaScript funcione no muestra nada justo cuando importa.

Para leer la API recibe una **credencial de sesión de solo lectura y quince minutos**, que no se
guarda en la base de datos y no puede escribir nada. Solo se entrega a quien entra por loopback —
alguien que ya tiene la base de datos en disco.

La página **no carga nada de fuera** y su `Content-Security-Policy` solo le permite hablar con el
nodo que la sirvió. Un dashboard que llama a casa filtra quién opera un nodo y cuánto gana.

### El saldo prepago: no le puedes mandar una factura a una llave pública

Un agente es un `did:key`: no tiene país, ni razón social, ni número fiscal, ni tarjeta. **No existe
legalmente.** Facturar a fin de mes solo funciona con empresas bajo contrato; con agentes no
funciona en absoluto.

Por eso cada emisión se descuenta de un saldo. Un solo mecanismo cubre los tres modelos:

| Límite de crédito | Comportamiento | Para quién |
|---|---|---|
| Sin límite | Mide pero nunca rechaza; el saldo se acumula | **Fase de lanzamiento.** Gratis, pero medido desde el día uno |
| `"0"` | Sin saldo, sin servicio | **Agentes.** Sin riesgo de impago, sin contracargos, sin identidad legal |
| `"250.00"` | Sirve hasta ese negativo | **Empresas.** El saldo negativo *es* la factura |

La medición nunca hay que añadirla después, y el día que enciendas el precio ya tendrás un año de
datos reales de uso.

**Un depósito registra que el dinero llegó; nunca recibe dinero.** El nodo no tiene credenciales de
pago. Tú confirmas la transferencia, el pago on-chain o el cobro de Stripe en la consola del
proveedor, y lo registras con esa referencia — un abono sin referencia es un saldo no auditable.

El cargo y su entrada en el registro son **una sola transacción**: nunca se emite un recibo sin
cobrarlo, ni se cobra sin emitirlo. Y `credits.audit()` recalcula cada saldo desde su libro mayor:
un total guardado que puede desviarse en silencio del libro del que sale es como los errores de
dinero sobreviven años.

> Esto necesita confirmación de un abogado antes de facturar el primer dólar. La estructura es
> sólida y común, pero no es mi terreno.

---

## 4. Estado actual

```
Uise/
├── spec/uip-1.md          Spec normativo. El producto real.
├── spec/schemas/          JSON Schema: envelope, descriptor, receipt
├── conformance/           La suite. Define qué "es" Uise. Cero dependencias.
├── uip/                   Núcleo del protocolo. Cero dependencias.
├── uise/                  SDK + nodo: suites de producción, agente, log, storage
├── tests/                 Pruebas del SDK y del nodo
├── demo.py                Plano de conversación (no necesita instalar nada)
└── demo_node.py           Plano de valor: emisión, anclaje, auditoría
```

| Fase | Qué | Estado |
|---|---|---|
| 0 | Cerrar el idioma con agilidad post-cuántica | **Hecho** |
| 1 | SDK — conectar un agente en 5 líneas | **Hecho** |
| 2 | El nodo — emisión y registro público | **Hecho** |
| 3 | Puentes a MCP y A2A | **Hecho** |
| 4 | Publicar con fecha y licencia | Pendiente |

### Los puentes (fase 3)

Existen ya miles de agentes construidos sobre MCP y A2A. Envolverlos cuesta unas líneas y **no
cambia ni una línea dentro del agente**: gana identidad criptográfica, mensajes firmados y recibos
por ser envuelto, no por ser reescrito.

**La traducción pierde información en una dirección, y ese es exactamente el punto:** ni MCP ni A2A
tienen dónde poner precio, SLA ni liquidación. Entrar a Uise los añade; salir los descarta. Si
alguno de los dos pudiera expresarlos, Uise sería un perfil de ese formato en vez de un protocolo.

Dos reglas, ambas verificadas por pruebas:

- Un identificador que no sobrevive la normalización se preserva en la extensión `x`. Un puente que
  renombra la herramienta de alguien en silencio está roto.
- **Ningún nombre de campo se inventa.** Omitir un campo se recupera; un nombre equivocado que
  parece autoritativo, no. Los mapeos se verificaron contra las especificaciones publicadas de MCP
  y A2A, no de memoria.

`uip/` y `uise/` son **una sola** implementación: el SDK registra criptografía más fuerte en el
mismo núcleo que verifica la suite de conformidad.

---

## 5. Fuera de alcance en v0.1

Blockchain · ZK proofs (circom) · gVisor / Firecracker · Temporal · Qdrant · etcd · ClickHouse ·
Redis · marketplace · stablecoins · SOC2 · monorepo turborepo.

Ninguno es necesario para que el protocolo funcione, y todos añaden peso muerto que mata la v0.1.

---

## 6. Números objetivo reales

| Métrica | Objetivo del plan original | Objetivo real | Nota |
|---|---|---|---|
| Throughput | 1M msg/s por la red de Uise | ~65k tx/s en el plano de valor | 1M msg/s = 15× Visa con ingreso cero |
| Latencia p95 | <50ms | <50ms en el plano de valor | El plano de conversación es P2P: latencia de red directa |
| Agentes | Trillones | Sin techo por diseño | Garantizado por topología, no por capacidad |
| Uptime | 99.99% | 99.99% en el plano de valor | El plano de conversación no depende de Uise |

---

## 7. Requisitos del entorno (pendientes)

- Python 3.12+ — actualmente 3.9.6
- Docker — no instalado
- Rust/cargo — presente
- Node/pnpm — no necesario (monorepo turborepo descartado)
