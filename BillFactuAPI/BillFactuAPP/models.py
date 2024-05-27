from django.db import models

class Usuario(models.Model):
    nombre = models.CharField(max_length=50, null=False, unique=True) # Este campo es para el nombre del usuario
    correo = models.EmailField(max_length=50, null=False, unique=True) # Este campo es para el correo del usuario
    contrasena = models.CharField(max_length=100, null=False) # Este campo es para la contraseña del usuario
    token = models.CharField(unique=True, max_length=45) # Este campo es para el token del usuario
    admin = models.BooleanField(default=False) # Este campo es para saber si el usuario es administrador
    jefe = models.BooleanField(default=False) # Este campo es para saber si el usuario es jefe de alguna empresa

class Empresa(models.Model):
    nombre = models.CharField(max_length=50, null=False) # Este campo es para el nombre de la empresa
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE) # Este campo es para la relacion con el usuario propietario

class Miembros(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE) # Este campo es para la relacion con el usuario
    empresa = models.ForeignKey(Empresa, on_delete=models.CASCADE) # Este campo es para la relacion con la empresa

class Factura(models.Model):
    empresa = models.ForeignKey(Empresa, on_delete=models.CASCADE) # Este campo es para la relacion con la empresa
    factura = models.FileField(upload_to='facturas/') # Este campo es para el almacenaje de las facturas
    fecha = models.DateField() # Este campo es para la fecha de la factura

class Prefactura(models.Model):
    empresa = models.ForeignKey(Empresa, on_delete=models.CASCADE) # Este campo es para la relacion con la empresa
    prefactura = models.FileField(upload_to='prefacturas/') # Este campo es para el almacenaje de las prefacturas
    fecha = models.DateField() # Este campo es para la fecha de la prefactura