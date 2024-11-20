from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, Tls
from ssl import CERT_NONE

# Configuración TLS para ignorar certificados en entornos de prueba
tls = Tls(validate=CERT_NONE)

def iniciar_sesion_ad(servidor, dominio, base_dn, usuario, password):
    upn = f"{usuario}@{dominio}"  # Formato usuario@dominio.local
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
        dn = f"CN={user_data['username']},{base_dn}"
        print(f"Intentando crear el usuario con DN: {dn}")
        #Diccionario con los atributos del usuario a crear - Revisar a partir de aqui
        atributos = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': user_data['username'],
            'givenName': user_data.get('givenName', ''),
            'sn': user_data.get('sn', ''),
            'sAMAccountName': user_data['username'],
            'userPassword': user_data['password'],
            'userAccountControl': 512  # Habilitar cuenta
        }
        # Intentar crear el usuario
        conn.add(dn, attributes=atributos)
        if conn.result['description'] == 'success':
            print(f"Usuario {user_data['username']} creado exitosamente en OU=USUARIOS.")
        else:
            print(f"Error al crear usuario: {conn.result['description']} - {conn.result['message']}")

    except Exception as e:
        print(f"Error al crear usuario: {e}")


def editar_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, username, user_data):
    try:
        conn = Connection(Server(servidor, use_ssl=servidor.startswith("ldaps"), tls=tls, get_info=ALL),
                          user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        dn = f"CN={username},{base_dn}"
        cambios = {key: [(MODIFY_REPLACE, [value])] for key, value in user_data.items()}
        conn.modify(dn, changes=cambios)
    except Exception as e:
        print(f"Error al editar usuario: {e}")


def eliminar_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, username):
    try:
        # Configurar conexión al servidor LDAP
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        # Construir el Distinguished Name (DN) del usuario
        user_dn = f"CN={username},{base_dn}"

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
        conn.search(base_dn, '(objectClass=user)', attributes=['cn', 'givenName', 'sn', 'mail'])
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
#         for key, value in user_data.items():
#             if isinstance(value, list) and len(value) > 0:
#                 user_data[key] = value[0]  # Tomar el primer elemento de la lista
#             elif isinstance(value, list):
#                 user_data[key] = ""  # Si la lista está vacía, asignar una cadena vacía
#         # Procesar grupos (memberOf)
# # Procesar grupos (memberOf)
#         if 'memberOf' in user_data and user_data['memberOf']:
#             if isinstance(user_data['memberOf'], list):
#                 user_data['memberOf'] = [
#                     grp.split(',')[0].split('=')[1] for grp in user_data['memberOf']
#                 ]
#             elif isinstance(user_data['memberOf'], str):
#                 user_data['memberOf'] = [user_data['memberOf'].split(',')[0].split('=')[1]]
#             else:
#                 user_data['memberOf'] = []
#         else:
            # user_data['memberOf'] = []


        user_data['memberOf'] = [
            grp.split(',')[0].split('=')[1] for grp in user_data.get('memberOf', [])
        ]

        return user_data, None

    except Exception as e:
        print(f"Error al obtener datos del usuario: {e}")
        return None, f"Error al obtener datos del usuario: {e}"

