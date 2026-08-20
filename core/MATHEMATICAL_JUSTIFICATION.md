## Justificación Matemática de la Arquitectura

### 1. Por qué máximo 5 endpoints (Hick's Law: T = b·log2(n+1))

El principio de Hick's Law nos dice que la complejidad percibida de una tarea aumenta en función del número de opciones disponibles. En nuestro caso, cada endpoint representa una decisión importante en la verificación de la entidad. Limitando a 5 endpoints, reducimos significativamente la complejidad percibida y facilitamos la adopción y la integración del sistema por parte de los desarrolladores.

### 2. Por qué pricing per-call vs por asiento (elasticidad precio-demanda)

El precio por llamada permite una mayor elasticidad de la demanda, permitiendo a los clientes pagar solo por lo que usan. Esto es especialmente beneficioso en un modelo de uso por operación, donde la complejidad y la utilización varían de sesión en sesión. Además, el modelo por llamada es más fácil de administrar y escalar en comparación con un modelo de suscripción fija.

### 3. Por qué esta estructura de datos específica (complejidad algorítmica)

Utilizamos una estructura de datos basada en árboles de decisión para gestionar las señales y los evidencias. La complejidad algorítmica de esta estructura es eficiente, ya que permite rápidas consultas y actualizaciones de los conteos en memoria. Esta estructura también facilita la incorporación de nuevos datos y la actualización de las probabilidades de manera independiente.

### 4. El invariante matemático que hace esta solución correcta

El invariante matemático es la propiedad que se mantiene constante durante el funcionamiento del sistema. En este caso, el invariante es que la suma de los conteos de evidencia debe ser igual a la cantidad total de evidencias registradas. Esta propiedad asegura que los cálculos de probabilidades y las decisiones de verificación sean consistentes y correctos.

$$ \sum_{i=1}^{n} \text{count}_i = \text{total\_evidences} $$

### 5. Límites teóricos del sistema (qué no puede hacer y por qué)

El sistema tiene un límite teórico de la cantidad de datos que puede procesar simultáneamente, lo que depende de la capacidad de la memoria y la velocidad de la CPU. Además, no puede manejar correctamente señales que no tienen una correspondencia real en la base de datos, ya que estos datos no tienen un valor de evidencia y por lo tanto no afectan la decisión de verificación.

Además, el sistema no puede manejar señales que son una combinación de señales verdaderas y falsas, ya que esto podría llevar a decisiones erróneas. Por ejemplo, si una señal de WHOIS se marca como falsa y una señal de DNS como verdadera, el sistema no podrá tomar una decisión correcta sin una lógica adicional para manejar estas combinaciones.