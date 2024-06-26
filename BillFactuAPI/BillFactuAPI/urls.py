"""
URL configuration for BillFactuAPI project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from BillFactuAPP import endpoints

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', endpoints.login),
    path('register/', endpoints.register),
    path('logout/', endpoints.logout),
    path('inicio/', endpoints.inicio),
    path('facturas/', endpoints.facturas),
    path('prefacturas/', endpoints.prefacturas),
    path('tokenvalido/', endpoints.token_valido),
    path('empresas/', endpoints.empresas),
    path('crearempresas/', endpoints.crear_empresas),
    path('unirempresa/', endpoints.unir_empresa),
    path('subirfactura/', endpoints.subir_factura),
    path('subirprefactura/', endpoints.subir_prefactura),
    path('descargarfactura/', endpoints.descargar_factura),
    path('descargarprefactura/', endpoints.descargar_prefactura),
    path('verempresas/', endpoints.ver_empresas),
]

#Este codigo es para poder servir los archivos en django con el modo debug activado en models, si esto se cambia dejaremos de poder mostrar los archivos
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)