from ldap3 import Server, Connection, ALL, MODIFY_REPLACE,MODIFY_ADD,MODIFY_DELETE, SUBTREE, Tls
from ssl import CERT_NONE

# Configuración TLS para ignorar certificados en entornos de prueba
tls = Tls(validate=CERT_NONE)

#Función para iniciar sesión
def iniciar_sesion_ad(servidor, dominio, base_dn, usuario, password):
    upn = f"{usuario}@{dominio}"  
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), tls=tls, get_info=ALL)
        conn = Connection(server, user=upn, password=password, auto_bind=True)
        
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
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
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
            'mail': user_data.get('mail', ''),
            'telephoneNumber': user_data.get('telephoneNumber', '')
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

#Función para editar usuario
def editar_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, atributos):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(
            server,
            user=f"{admin_user}@{dominio}",
            password=admin_pass,
            auto_bind=True
        )

        user_dn = atributos.pop("distinguishedName")  #Usamos el DN para identificar el usuario
        cambios = {attr: [(MODIFY_REPLACE, [val])] for attr, val in atributos.items() if val}

        conn.modify(user_dn, changes=cambios)

        if conn.result["result"] == 0:
            print("Usuario editado correctamente.")
            return True
        else:
            print(f"Error al editar el usuario: {conn.result['description']}")
            return False
    except Exception as e:
        print(f"Error al editar usuario en AD: {e}")
        return False

#Función para eliminar usuario
def eliminar_usuario_ad(servidor, dominio, base_dn, admin_user, admin_pass, username):
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        # Conseguir UO donde está guardado el usuario
        search_filter = f"(sAMAccountName={username})"
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName'])

        user_dn = conn.entries[0].distinguishedName.value
        conn.delete(user_dn)

        if conn.result['description'] == 'success':
            print(f"Usuario {username} eliminado correctamente.")
        else:
            print(f"Error al eliminar usuario: {conn.result['description']}")

    except Exception as e:
        print(f"Error al eliminar usuario: {e}")

#Función para obtener usuarios
def obtener_usuarios_ad(servidor, dominio, base_dn):
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)

        admin_user = f"Administrador@{dominio}"  
        admin_pass = "abc123.."  

        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)

        conn.search(base_dn, '(objectClass=user)', attributes=['cn', 'givenName', 'sn', 'mail','distinguishedName' ])
        usuarios = [entry.entry_attributes_as_dict for entry in conn.entries]
        return usuarios

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []

#Función para sacar los detalles de todos los usuarios
def obtener_detalle_usuario(servidor, dominio, base_dn, admin_user, admin_pass, username):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        filtro = f"(sAMAccountName={username})"
        atributos = ['cn', 'givenName', 'sn', 'mail', 'memberOf', 'distinguishedName', 'telephoneNumber']

        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            return None, f"Usuario {username} no encontrado en el dominio."

        user_data = conn.entries[0].entry_attributes_as_dict

        user_data['memberOf'] = [
            grp.split(',')[0].split('=')[1] for grp in user_data.get('memberOf', [])
        ]

        return user_data, None

    except Exception as e:
        print(f"Error al obtener datos del usuario: {e}")
        return None, f"Error al obtener datos del usuario: {e}"

#Función para sacar los detalles del usuario a editar
def obtener_detalle_usuario2(servidor, dominio, base_dn, admin_user, admin_pass, username):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(
            server,
            user=f"{admin_user}@{dominio}",
            password=admin_pass,
            auto_bind=True
        )

        filtro = f"(sAMAccountName={username})"
        atributos = ["givenName", "sn", "mail", "telephoneNumber", "distinguishedName"]
        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            print(f"No se encontró el usuario: {username}")
            return None

        entry = conn.entries[0]
        user_data = {
            "givenName": entry.givenName.value,
            "sn": entry.sn.value,
            "mail": entry.mail.value,
            "telephoneNumber": entry.telephoneNumber.value,
            "distinguishedName": entry.distinguishedName.value,
        }
        print(f"Datos recuperados: {user_data}")
        return user_data

    except Exception as e:
        print(f"Error al obtener datos del usuario: {e}")
        return None

#Función para sacar los detalles de todos los equipos del dominio
def obtener_detalle_equipo(servidor, dominio, base_dn, admin_user, admin_pass, cn):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        filtro = f"(cn={cn})"
        atributos = ['cn',  'dNSHostName', 'operatingSystem', 'whenCreated', 'description']

        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            return None, f"Equipo {cn} no encontrado en el dominio."

        computer_data = conn.entries[0].entry_attributes_as_dict
        return computer_data, None

    except Exception as e:
        print(f"Error al obtener datos del equipo: {e}")
        return None, f"Error al obtener datos del equipo: {e}"

#Función para crear grupo
def crear_grupo_ad(servidor, dominio, base_dn, admin_user, admin_pass, user_data):
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        if user_data.get('UO'): 
            dn = f"cn={user_data['group_name']},ou={user_data.get('UO')},{base_dn}" 
        else:
            dn = f"cn={user_data['group_name']},{base_dn}"        
        atributos_grupo = {
            'objectClass': ['top', 'group'],
            'cn':  user_data['group_name'],
            'description': user_data.get('descripcion', ''),
            'sAMAccountName': user_data['group_name'],
        }
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
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)

        admin_user = f"Administrador@{dominio}" 
        admin_pass = "abc123.." 

        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)

        conn.search(base_dn, '(objectClass=groupPolicyContainer)' , search_scope=SUBTREE, attributes=['cn', 'displayName', 'gPCFileSysPath', 'versionNumber' ])
        gpos = [entry.entry_attributes_as_dict for entry in conn.entries]
        print(gpos)
        return gpos

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []

#Función para obtener grupos
def obtener_grupos(servidor, dominio, base_dn):
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)

        admin_user = f"Administrador@{dominio}"  
        admin_pass = "abc123.."  

        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)

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
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)

        admin_user = f"Administrador@{dominio}"  
        admin_pass = "abc123.." 

        conn = Connection(server, user=admin_user, password=admin_pass, auto_bind=True)

        conn.search(base_dn, '(objectClass=computer)' , search_scope=SUBTREE, attributes=['cn', 'distinguishedName' ])
        grupos = [entry.entry_attributes_as_dict for entry in conn.entries]
        print(grupos)
        return grupos

    except Exception as e:
        print(f"Error al obtener usuarios del AD: {e}")
        return []

#Función para sacar los detalles de todos los grupo del dominio
def obtener_detalle_grupo(servidor, dominio, base_dn, admin_user, admin_pass, cn):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        filtro = f"(cn={cn})"
        atributos = ['cn',  'member', 'memberOf', 'distinguishedName', 'description']

        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            return None, f"Grupo {cn} no encontrado en el dominio."

        group_data = conn.entries[0].entry_attributes_as_dict
        # Procesar "member" para extraer solo los CN
        group_data["member"] = [
            dn.split(",")[0].split("=")[1] if "CN=" in dn else dn
            for dn in group_data.get("member", [])
        ]

        # Procesar "memberOf" para extraer solo los CN
        group_data["memberOf"] = [
            dn.split(",")[0].split("=")[1] if "CN=" in dn else dn
            for dn in group_data.get("memberOf", [])
        ]

        return group_data, None

    except Exception as e:
        print(f"Error al obtener datos del grupo: {e}")
        return None, f"Error al obtener datos del grupo: {e}"    

#Función restablecer contraseña propia
def cambiar_contrasena_ad(servidor, dominio, base_dn, admin_user, admin_pass, new_password):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        search_filter = f"(sAMAccountName={admin_user})"
        conn.search(base_dn, search_filter, attributes=['distinguishedName'])

        if not conn.entries:
            raise Exception(f"Usuario '{admin_user}' no encontrado en el dominio.")

        user_dn = conn.entries[0].entry_dn

        conn.extend.microsoft.modify_password(user_dn, new_password)

        if conn.result['result'] == 0:
            print("Contraseña cambiada exitosamente.")
        else:
            raise Exception(f"Error al cambiar la contraseña: {conn.result['description']}")

    except Exception as e:
        raise Exception(f"No se pudo cambiar la contraseña: {str(e)}")

#Función eliminar grupos
def eliminar_grupos_ad(servidor, dominio, base_dn, admin_user, admin_pass, cn):
    try:
        server = Server(servidor, use_ssl=servidor.startswith("ldaps"), get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)
        search_filter = f"(cn={cn})"
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=['distinguishedName'])

        group_dn = conn.entries[0].distinguishedName.value

        conn.delete(group_dn)

        if conn.result['description'] == 'success':
            print(f"Grupo {group_dn} eliminado correctamente.")
        else:
            print(f"Error al eliminar grupo: {conn.result['description']}")

    except Exception as e:
        print(f"Error al eliminar gruopo: {e}")

#Función para sacar detalles de las GPOS
def obtener_detalle_gpo(servidor, dominio, base_dn, admin_user, admin_pass, cn):
    try:
        server = Server(servidor, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{admin_user}@{dominio}", password=admin_pass, auto_bind=True)

        filtro = f"(cn={cn})"
        atributos = ['cn', 'displayName', 'distinguishedName', 'gPCFileSysPath', 'whenCreated']

        conn.search(base_dn, filtro, attributes=atributos)

        if not conn.entries:
            return None, f"GPO {cn} no encontrada en el dominio."

        gpo_data = conn.entries[0].entry_attributes_as_dict

        return gpo_data, None

    except Exception as e:
        print(f"Error al obtener datos de la GPO: {e}")
        return None, f"Error al obtener datos de la GPO: {e}"
