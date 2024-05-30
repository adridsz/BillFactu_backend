from django.contrib import admin

# Register your models here.

from .models import Usuario, Empresa, Miembros, Factura, Prefactura

admin.site.register(Usuario)
admin.site.register(Empresa)
admin.site.register(Miembros)
admin.site.register(Factura)
admin.site.register(Prefactura)
