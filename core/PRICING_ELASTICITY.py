import numpy as np

# Funcion de demanda: Q = a * P^-b
def demanda(P, a=100000, b=0.5):
    """Funcion de demanda que describe como el volumen de operaciones disminuye con el precio."""
    return a * P**-b

# Elasticidad precio-demanda
def elasticidad(P, a=100000, b=0.5):
    """Calculo de la elasticidad de precio-demanda -- autocontenida (a, b explicitos, no variables de otra funcion)."""
    Q = demanda(P, a=a, b=b)
    dQ_dP = -b * a * P**(-b-1)
    return (dQ_dP * P / Q)

# Precio optimo que maximiza revenue
def precio_optimo(Q, b=0.5):
    """Calculo del precio optimo que maximiza el revenue."""
    return Q / (1 - b)

# Escenarios de adopcion
scenarios = [
    {'segmento': 'early_adopter', 'precio': 0.01, 'volumen_mensual': 5000},
    {'segmento': 'mid_market', 'precio': 0.02, 'volumen_mensual': 50000},
    {'segmento': 'enterprise', 'precio': 0.04, 'volumen_mensual': 500000},
]

# Punto de equilibrio freemium->paid
def punto_equilibrio(scenarios):
    """Calculo del punto de equilibrio entre el modelo freemium y el modelo pago."""
    lines = list(map(
        lambda s: f"Segmento: {s['segmento']}, Precio: {s['precio']}, Volumen: {s['volumen_mensual']}, Revenue: {s['precio'] * s['volumen_mensual']}",
        scenarios,
    ))
    print("\n".join(lines))
    return scenarios
