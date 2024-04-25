import secrets

import bcrypt
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from BillFactuAPP.models import Usuario


@csrf_exempt
def login(request):
    if request.method == 'POST':
        body_json = json.loads(request.body)
        if 'nombre' not in body_json or 'contrasena' not in body_json:
            return JsonResponse({'error': 'Faltan parámetros o parámetros incorrectos'}, status=400)

        json_nombre = body_json['nombre']
        json_password = body_json['contrasena']

        try:
            usuario = Usuario.objects.get(nombre=json_nombre)
        except Usuario.DoesNotExist:
            try:
                usuario = Usuario.objects.get(correo=json_nombre)
            except Usuario.DoesNotExist:
                return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        if bcrypt.checkpw(json_password.encode('utf-8'), usuario.contrasena.encode('utf-8')):
            return JsonResponse({'token': usuario.token})
        else:
            return JsonResponse({'error': 'Contraseña incorrecta'}, status=400)


@csrf_exempt
def register(request):
    if request.method == 'POST':
        body_json = json.loads(request.body)
        if 'nombre' not in body_json or 'correo' not in body_json or 'contrasena' not in body_json:
            return JsonResponse({'error': 'Faltan parámetros o parámetros incorrectos'}, status=400)

        json_nombre = body_json['nombre']
        json_correo = body_json['correo']
        json_password = body_json['contrasena']

        if Usuario.objects.filter(nombre=json_nombre).exists() or Usuario.objects.filter(correo=json_correo).exists():
            return JsonResponse({'error': 'El usuario o el correo ya existe'}, status=400)

        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(json_password.encode('utf-8'), salt)

        token = secrets.token_hex(10)

        usuario = Usuario(nombre=json_nombre, correo=json_correo, contrasena=hashed.decode('utf-8'), token=token)
        usuario.save()

        return JsonResponse({'token': usuario.token})
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)