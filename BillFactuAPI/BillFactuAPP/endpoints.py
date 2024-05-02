# Importamos los módulos necesarios
import secrets
import bcrypt
import json

# Importamos JsonResponse para devolver respuestas JSON
# Importamos csrf_exempt para eliminar la protección CSRF
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Importamos el modelo Usuario
from BillFactuAPP.models import Usuario

# Definimos la vista para el inicio de sesión
@csrf_exempt
def login(request):
    # Verificamos si el método de la solicitud es POST
    if request.method == 'POST':
        # Convertimos el cuerpo de la solicitud a JSON
        body_json = json.loads(request.body)
        # Verificamos si los parámetros necesarios están presentes
        if 'nombre' not in body_json or 'contrasena' not in body_json:
            # Si no, devolvemos un error
            return JsonResponse({'error': 'Faltan parámetros o parámetros incorrectos'}, status=400)

        # Obtenemos los parámetros de la solicitud
        json_nombre = body_json['nombre']
        json_password = body_json['contrasena']

        # Intentamos obtener el usuario por el nombre
        try:
            usuario = Usuario.objects.get(nombre=json_nombre)
        except Usuario.DoesNotExist:
            # Si no existe, intentamos obtenerlo por el correo
            try:
                usuario = Usuario.objects.get(correo=json_nombre)
            except Usuario.DoesNotExist:
                # Si no existe, devolvemos un error
                return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Verificamos si la contraseña es correcta
        if bcrypt.checkpw(json_password.encode('utf-8'), usuario.contrasena.encode('utf-8')):
            # Si es correcta, devolvemos el token del usuario
            return JsonResponse({'token': usuario.token})
        else:
            # Si no es correcta, devolvemos un error
            return JsonResponse({'error': 'Contraseña incorrecta'}, status=400)

# Definimos la vista para el registro
@csrf_exempt
def register(request):
    # Verificamos si el método de la solicitud es POST
    if request.method == 'POST':
        # Convertimos el cuerpo de la solicitud a JSON
        body_json = json.loads(request.body)
        # Verificamos si los parámetros necesarios están presentes
        if 'nombre' not in body_json or 'correo' not in body_json or 'contrasena' not in body_json:
            # Si no, devolvemos un error
            return JsonResponse({'error': 'Faltan parámetros o parámetros incorrectos'}, status=400)

        # Obtenemos los parámetros de la solicitud
        json_nombre = body_json['nombre']
        json_correo = body_json['correo']
        json_password = body_json['contrasena']

        # Verificamos si el usuario o el correo ya existen
        if Usuario.objects.filter(nombre=json_nombre).exists() or Usuario.objects.filter(correo=json_correo).exists():
            # Si existen, devolvemos un error
            return JsonResponse({'error': 'El usuario o el correo ya existe'}, status=400)

        # Generamos la sal y la contraseña cifrada
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(json_password.encode('utf-8'), salt)

        # Generamos un token
        token = secrets.token_hex(10)

        # Creamos el usuario
        usuario = Usuario(nombre=json_nombre, correo=json_correo, contrasena=hashed.decode('utf-8'), token=token)
        # Guardamos el usuario
        usuario.save()

        # Devolvemos el token del usuario
        return JsonResponse({'token': usuario.token})
    else:
        # Si el método de la solicitud no es POST, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)