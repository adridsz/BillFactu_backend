# Importamos los módulos necesarios
import secrets
import bcrypt
import json

# Importamos JsonResponse para devolver respuestas JSON
# Importamos csrf_exempt para eliminar la protección CSRF
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Importamos el modelo Usuario
from BillFactuAPP.models import Usuario, Empresa, Miembros, Factura, Prefactura


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
            # Si es correcta, devolvemos el token del usuario y si es jefe o no
            return JsonResponse({'token': usuario.token, 'jefe': usuario.jefe})
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
        if 'nombre' not in body_json or 'correo' not in body_json or 'contrasena' not in body_json or 'jefe' not in body_json:
            # Si no, devolvemos un error
            return JsonResponse({'error': 'Faltan parámetros o parámetros incorrectos'}, status=400)

        # Obtenemos los parámetros de la solicitud
        json_nombre = body_json['nombre']
        json_correo = body_json['correo']
        json_password = body_json['contrasena']
        json_jefe = body_json['jefe']

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
        usuario = Usuario(nombre=json_nombre, correo=json_correo, contrasena=hashed.decode('utf-8'), token=token, jefe=json_jefe)
        # Guardamos el usuario
        usuario.save()

        # Devolvemos el token del usuario
        return JsonResponse({'token': usuario.token})
    else:
        # Si el método de la solicitud no es POST, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

# Definimos la vista para el cierre de sesión
def logout(request):
    # Verificamos si el método de la solicitud es POST
    if request.method == 'POST':
        # Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)

        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Volvemos a generar el token, para cerrar la sesión y que el usuario a la hora de volver a iniciar sesión, tenga un nuevo token ya que no podemos borrarlo y dejarlo vacio porque el token es un campo obligatorio
        usuario.token = secrets.token_hex(10)
        # Guardamos el usuario
        usuario.save()

        # Devolvemos un mensaje de éxito
        return JsonResponse({'mensaje': 'Cierre de sesión exitoso'})
    else:
        # Si el método de la solicitud no es DELETE, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def inicio(request):
    # Verificamos si el método de la solicitud es GET
    if request.method == 'GET':
        #Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)
        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
    #Comprobamos si el usuario es jefe
        if usuario.jefe:
            # Obtenemos la empresa del usuario
            empresa = Empresa.objects.get(usuario=usuario)
            # Devolvemos el nombre de la empresa
            return JsonResponse({'empresa': empresa.nombre})
        else:
            # Obtenemos las empresas del usuario
            empresas = Miembros.objects.filter(usuario=usuario)
            # Devolvemos los nombres de las empresas
            return JsonResponse({'empresas': [empresa.empresa.nombre for empresa in empresas]})
    else:
        # Si el método de la solicitud no es GET, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def facturas(request):
    # Verificamos si el método de la solicitud es GET
    if request.method == 'GET':
        # Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)

        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Obtenemos la empresa a la que quiere acceder el usuario la cual es enviada en el cuerpo de la solicitud
        body_json = json.loads(request.body)
        json_empresa = body_json['empresa']
        # Intentamos obtener la empresa por el nombre
        try:
            empresa = Empresa.objects.get(nombre=json_empresa)
        except Empresa.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Empresa no encontrada'}, status=404)
        # Obtenemos las facturas de la empresa y las fechas de las facturas
        facturas = Factura.objects.filter(empresa=empresa)
        fechas = [factura.fecha for factura in facturas]
        # Devolvemos las fechas de las facturas
        return JsonResponse({'fechas': fechas})
    else:
        # Si el método de la solicitud no es GET, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def prefacturas(request):
    # Verificamos si el método de la solicitud es GET
    if request.method == 'GET':
        # Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)

        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Obtenemos la empresa a la que quiere acceder el usuario la cual es enviada en el cuerpo de la solicitud
        body_json = json.loads(request.body)
        json_empresa = body_json['empresa']
        # Intentamos obtener la empresa por el nombre
        try:
            empresa = Empresa.objects.get(nombre=json_empresa)
        except Empresa.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Empresa no encontrada'}, status=404)
        # Obtenemos las prefacturas de la empresa y las fechas de las prefacturas
        prefacturas = Prefactura.objects.filter(empresa=empresa)
        fechas = [prefactura.fecha for prefactura in prefacturas]
        # Devolvemos las fechas de las prefacturas
        return JsonResponse({'fechas': fechas})
    else:
        # Si el método de la solicitud no es GET, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def token_valido(request):
    # Verificamos si el método de la solicitud es GET
    if request.method == 'GET':
        # Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)

        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Devolvemos un mensaje de éxito
        return JsonResponse({'mensaje': 'Token válido'})
    else:
        # Si el método de la solicitud no es GET, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def empresas(request):
    # Verificamos si el método de la solicitud es GET
    if request.method == 'GET':
        # Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)

        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Obtenemos todas las empresas de nuestra aplicación
        empresas = Empresa.objects.all()
        # Creamos una lista vacía para almacenar las empresas
        empresas_list = []

        # Devolvemos la lista de empresas
        return JsonResponse(empresas_list, safe=False)
    else:
        # Si el método de la solicitud no es GET, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)

def crear_empresas(request):
    # Verificamos si el método de la solicitud es POST
    if request.method == 'POST':
        # Obtenemos el token de la solicitud
        token = request.headers.get('Authorization')
        # Verificamos si el token está presente
        if token is None:
            # Si no está presente, devolvemos un error
            return JsonResponse({'error': 'Token no encontrado'}, status=404)

        # Intentamos obtener el usuario por el token
        try:
            usuario = Usuario.objects.get(token=token)
        except Usuario.DoesNotExist:
            # Si no existe, devolvemos un error
            return JsonResponse({'error': 'Usuario no encontrado'}, status=404)

        # Obtenemos el nombre de la empresa de la solicitud
        body_json = json.loads(request.body)
        json_nombre = body_json['nombre']

        # Comprobamos si el usuario es jefe antes de crear la empresa
        if usuario.jefe == False:
            # Si no es jefe, devolvemos un error
            return JsonResponse({'error': 'No tienes permisos para crear una empresa'}, status=403)

        # Creamos la empresa
        empresa = Empresa(nombre=json_nombre, usuario=usuario)
        # Guardamos la empresa
        empresa.save()

        # Devolvemos un mensaje de éxito
        return JsonResponse({'mensaje': 'Empresa creada correctamente'})
    else:
        # Si el método de la solicitud no es POST, devolvemos un error
        return JsonResponse({'error': 'Método no permitido'}, status=405)