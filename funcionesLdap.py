from ldap3 import Server, Connection, ALL, MODIFY_REPLACE,MODIFY_ADD, SUBTREE, Tls
from ssl import CERT_NONE

# Configuración TLS para ignorar certificados en entornos de prueba
tls = Tls(validate=CERT_NONE)

def iniciar_sesion_ad(servidor, dominio, base_dn, usuario, password):
    upn = f"{usuario}@{dominio}"  
    try:
        # Configuración del servidor LDAP con soporte de LDAPS
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), tls=tls, get_info=ALL)
        conn = Connection(server, user=upn, password=password, auto_bind=True)

        # Búsqueda del usuario en el Active Directory
        filtro = f"(sAMAccountName={usuario})"
        atributos = ['cn', 'givenName', 'sn', 'mail', 'memberOf', 'distinguishedName']
        conn.search(base_dn, filtro, attributes=atributos)

        if conn.entries:
            user_data = conn.entries[0].entry_attributes_as_dict
            user_data['memberOf'] = [grp.split(',')[0].split('=')[1] for grp in user_data.get('memberOf', [])]
            return user_data, None
        else:
            return None, "Usuario no encontrado."

    except Exception as e:
        return None, str(e)

#Función para crear usuario
def crear_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, user_data):
    try:
        #Nos conectamos al servidor mediante LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        # Construir el DN donde se guardará el usuario creado
        if user_data.get('UO'): 
            dn = f"cn={user_data['username']},ou={user_data.get('UO')},{base_dn}" 
        else:
            dn = f"cn={user_data['username']},{base_dn}" 

        #Diccionario con los atributos del usuario a crear
        atributos = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': user_data['username'],
            'givenName': user_data.get('givenName', ''),
            'sn': user_data.get('sn', ''),
            'sAMAccountName': user_data['username'],
            'userAccountControl': 546,  #La cuenta está deshabilitada
            'mail': user_data.get('mail', '')
        }
        #Crear el usuario 
        conn.add(dn, attributes=atributos)
        if conn.result['description'] == 'success':
            print(f"Usuario {user_data['username']} creado exitosamente en OU=USUARIOS.")
            #Habilitamos cuenta, metemos en el grupo y creamos contraseña
            conn.extend.microsoft.modify_password(dn, user_data['password'])    #Le ponemos la contraseña al usuario
            conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})  #Habilitamos el usuario
            if user_data.get('UO'): 
                dn_grupo = f"cn={user_data.get('grupo')},ou={user_data.get('UO')},{base_dn}"
            else:
                dn_grupo = f"cn={user_data.get('grupo')},{base_dn}"

            conn.modify(dn_grupo, {'member': [(MODIFY_ADD, [dn])]}) 
        else:
            print(f"Error al crear usuario: {conn.result['description']} - {conn.result['message']}")

    except Exception as e:
        print(f"Error al crear usuario: {e}")


def editar_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, atributos):
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), tls=tls, get_info=ALL)
        conn = Connection(server,user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        
        #cambios = {key: [(MODIFY_REPLACE, [value])] for key, value in user_data.items()}
        cambios = {attr: [(MODIFY_REPLACE, [val])] for attr, val in atributos.items()}
        conn.modify(base_dn, changes=cambios)
        # Obtener los datos del usuario
        #usuario = conn.entries[0].entry_attributes_as_dict
        #usuario['dn'] = conn.entries[0].entry_dn

    except Exception as e:
        print(f"Error al editar usuario: {e}")

def eliminar_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, username):
    try:
        # Configurar conexión al servidor LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        # Conseguir UO donde está guardado el usuario
        search_filter = f"(sAMAccountName={username})"
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName'])


        # Construir el Distinguished Name (DN) del usuario
        user_dn = conn.entries[0].distinguishedName.value

        # Intentar eliminar el usuario
        conn.delete(user_dn)

        if conn.result['description'] == 'success':
            print(f"Usuario {username} eliminado correctamente.")
        else:
            print(f"Error al eliminar usuario: {conn.result['description']}")

    except Exception as e:
        print(f"Error al eliminar usuario: {e}")


def obtener_usuarios_ad(servidor, dominio, base_dn):
    try:
        # Configurar el servidor con LDAPS o LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)

        # Usuario administrador (cambiar por uno válido)
        admin_user = f"Administrador@{dominio}"  # Formato UPN
        admin_pass = "abc123.."  # Cambiar por la contraseña real

        # Conexión al servidor
        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)

        # Búsqueda de usuarios
        #search_filter = '(|(objectClass=user)(objectClass=group))'

        conn.search(base_dn, '(objectClass=user)', attributes=['cn', 'givenName', 'sn', 'mail','distinguishedName' ])
        usuarios = [entry.entry_attributes_as_dict for entry in conn.entries]
        return usuarios

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []


#Función para sacar los detalles de todos los usuarios del dominio
def obtener_detalle_usuario(servidor, dominio, base_dn, admin_user, admin_pass, username):
    try:
        # Conexión al servidor LDAP
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        # Filtro para buscar al usuario
        filtro = f"(sAMAccountName={username})"
        atributos = ['cn', 'givenName', 'sn', 'mail', 'memberOf', 'distinguishedName']

        # Realizar la búsqueda
        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            return None, f"Usuario {username} no encontrado en el dominio."

        # Procesar datos del usuario
        user_data = conn.entries[0].entry_attributes_as_dict

        user_data['memberOf'] = [
            grp.split(',')[0].split('=')[1] for grp in user_data.get('memberOf', [])
        ]

        return user_data, None

    except Exception as e:
        print(f"Error al obtener datos del usuario: {e}")
        return None, f"Error al obtener datos del usuario: {e}"

#Función para sacar los detalles de todos los equipos del dominio
def obtener_detalle_equipo(servidor, dominio, base_dn, admin_user, admin_pass, cn):
    try:
        # Conexión al servidor LDAP
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        # Filtro para buscar al usuario
        filtro = f"(cn={cn})"
        atributos = ['cn',  'dNSHostName', 'operatingSystem', 'whenCreated', 'description']

        # Realizar la búsqueda
        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            return None, f"Usuario {cn} no encontrado en el dominio."

        # Procesar datos del usuario
        user_data = conn.entries[0].entry_attributes_as_dict


        return user_data, None

    except Exception as e:
        print(f"Error al obtener datos del usuario: {e}")
        return None, f"Error al obtener datos del usuario: {e}"

#Función para crear grupo
def crear_grupo_ad(servidor, dominio, base_dn, admin_user, admin_pass, user_data):
    try:
        #Nos conectamos al servidor mediante LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        # Construir el DN donde se guardará el grupo creado
        if user_data.get('UO'): 
            dn = f"cn={user_data['group_name']},ou={user_data.get('UO')},{base_dn}" 
        else:
            dn = f"cn={user_data['group_name']},{base_dn}"         #Diccionario con los atributos del grupo a crear
        atributos_grupo = {
            'objectClass': ['top', 'group'],
            'cn':  user_data['group_name'],
            'description': user_data.get('descripcion', ''),
            'sAMAccountName': user_data['group_name'],
            #'mail': user_data.get('mail', '')
        }
        #Crear el grupo
        conn.add(dn, attributes=atributos_grupo)
        if conn.result['description'] == 'success':
            #Metemos en grupo y metemos miembros
            if user_data.get('UO'): 
                dn_grupo_miembros = f"cn={user_data.get('miembros')},ou={user_data.get('UO')},{base_dn}"
            else:
                dn_grupo_miembros = f"cn={user_data.get('miembros')},{base_dn}"
            dn_grupo_superior = f"cn={user_data.get('grupos_superiores')},{base_dn}"
            conn.modify(dn_grupo_superior, {'member': [(MODIFY_ADD, [dn])]}) 
            conn.modify(dn, {'member': [(MODIFY_ADD, [dn_grupo_miembros])]}) 
        else:
            print(f"Error al crear grupo: {conn.result['description']} - {conn.result['message']}")

    except Exception as e:
        print(f"Error al crear grupo: {e}")


#Función obtener gpos
def obtener_gpos(servidor, dominio, base_dn):
    try:
        # Configurar el servidor con LDAPS o LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
              # Usuario administrador (cambiar por uno válido)
        admin_user = f"Administrador@{dominio}"  # Formato UPN
        admin_pass = "abc123.."  # Cambiar por la contraseña real

        # Conexión al servidor
        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)
        # Búsqueda de usuarios
        conn.search(base_dn, '(objectClass=groupPolicyContainer)' , search_scope=SUBTREE, attributes=['cn', 'displayName', 'gPCFileSysPath', 'versionNumber' ])
        gpos = [entry.entry_attributes_as_dict for entry in conn.entries]
        print(gpos)
        return gpos

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []
    
def obtener_grupos(servidor, dominio, base_dn):
    try:
        # Configurar el servidor con LDAPS o LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
              # Usuario administrador (cambiar por uno válido)
        admin_user = f"Administrador@{dominio}"  # Formato UPN
        admin_pass = "abc123.."  # Cambiar por la contraseña real

        # Conexión al servidor
        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)
        # Búsqueda de usuarios
        conn.search(base_dn, '(objectClass=group)' , search_scope=SUBTREE, attributes=['cn', 'distinguishedName' ])
        grupos = [entry.entry_attributes_as_dict for entry in conn.entries]
        print(grupos)
        return grupos

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []

#Funcion obtener equipos
def obtener_equipos(servidor, dominio, base_dn):
    try:
        # Configurar el servidor con LDAPS o LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
              # Usuario administrador (cambiar por uno válido)
        admin_user = f"Administrador@{dominio}"  # Formato UPN
        admin_pass = "abc123.."  # Cambiar por la contraseña real

        # Conexión al servidor
        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)
        # Búsqueda de usuarios
        conn.search(base_dn, '(objectClass=computer)' , search_scope=SUBTREE, attributes=['cn', 'distinguishedName' ])
        grupos = [entry.entry_attributes_as_dict for entry in conn.entries]
        print(grupos)
        return grupos

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []