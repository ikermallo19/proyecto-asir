from flask import Flask, render_template, request, redirect, url_for, flash, session
from funcionesLdap import iniciar_sesion_ad, crear_usuario_ad, editar_usuario_ad, eliminar_usuario_ad, obtener_usuarios_ad, obtener_detalle_usuario, crear_grupo_ad, obtener_gpos, obtener_grupos, obtener_equipos, obtener_detalle_equipo, obtener_detalle_grupo, cambiar_contrasena_ad, eliminar_grupos_ad, obtener_detalle_usuario2, obtener_detalle_gpo
import logging
from logging.handlers import TimedRotatingFileHandler

app = Flask(__name__)
app.secret_key = 'secret_key'

#Configuración de los logs 
logger = logging.getLogger()  
logger.setLevel(logging.INFO) 
handler = TimedRotatingFileHandler('logs/system.log', when='W0', interval=1, backupCount=4)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Configuración del servidor Active Directory
AD_SERVER = 'ldaps://leon.datanet.local'    #Servidor Active Directory
AD_DOMAIN = 'datanet.local'                 #Dominio
AD_BASE_DN = 'ou=USUARIOS,ou=DATANET,dc=datanet,dc=local'   #Ruta busqueda usuarios y grupos
AD_BASE_DN_EQUIPOS = 'ou=EQUIPOS,ou=DATANET,dc=datanet,dc=local'   #Ruta busqueda equipos
AD_BASE_GPO = 'CN=Policies,CN=System,DC=datanet,DC=local'           #Ruta busqueda politicas de grupo

#Iniciar sesión
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Intentamos iniciar sesión en el AD
        user_data, error = iniciar_sesion_ad(AD_SERVER, AD_DOMAIN, AD_BASE_DN, username, password)

        if error:
            flash("Usuario y/o contraseña incorrectos", "danger")
            return redirect(url_for("login"))

        # Guardar datos en la sesión
        session['username'] = username
        session['user_data'] = user_data
        session['user_data']['password'] = password  # Guardar la contraseña en la sesión
        session['is_admin'] = "Administradores" in user_data.get('memberOf', [])

        flash("Inicio de sesión exitoso.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

#Cerrar Sesión
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

#Pantalla inicio
@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for("login"))

    is_admin = session.get('is_admin', False)

    return render_template("dashboard.html", username=session['username'], is_admin=is_admin)
#Pantalla Usuarios
@app.route("/user")
def user():
    if 'username' not in session:
        return redirect(url_for("login"))

    is_admin = session.get('is_admin', False)
    users = obtener_usuarios_ad(AD_SERVER, AD_DOMAIN, AD_BASE_DN)

    return render_template("users.html", username=session['username'], is_admin=is_admin, users=users)
#Pantalla Grupos
@app.route("/grupo")
def grupo():
    if 'username' not in session:
        return redirect(url_for("login"))
    
    is_admin = session.get('is_admin', False)
    grupos = obtener_grupos(AD_SERVER, AD_DOMAIN, AD_BASE_DN)
    return render_template("group.html", username=session['username'], is_admin=is_admin, grupos=grupos)

#Pantalla GPO
@app.route("/gpo")
def gpo():
    if 'username' not in session:
        return redirect(url_for("login"))
    
    is_admin = session.get('is_admin', False)
    gpos = obtener_gpos(AD_SERVER, AD_DOMAIN, AD_BASE_GPO)
    return render_template("gpo.html", username=session['username'], is_admin=is_admin, gpos=gpos)

#Pantalla Logs
@app.route("/logs")
def logs():
    if 'username' not in session:
        return redirect(url_for("login"))
    logger.info(f"Acceso a la página de logs por el usuario.")
    log_file_path = 'logs/app.log'
    logs= []
    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                logs.append(line.strip())
    except FileNotFoundError:
        logs.append ("Archivo de logs no encontrado")
    return render_template('logs.html',logs=logs)

#Pantalla Equipos
@app.route("/computer")
def computer():
    if 'username' not in session:
        return redirect(url_for("login"))
    
    is_admin = session.get('is_admin', False)
    computers = obtener_equipos(AD_SERVER, AD_DOMAIN, AD_BASE_DN_EQUIPOS)
    return render_template("computer.html", username=session['username'], is_admin=is_admin, computers=computers)

#Cambio contraseña
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # Verificar si el usuario está autenticado
    if 'username' not in session:
        flash("Debes iniciar sesión primero.", "danger")
        return redirect(url_for("login"))

    # Si el método es GET, se muestra el formulario
    if request.method == "GET":
        return render_template("restablecer_password.html")

    # Si el método es POST, se procesa el formulario
    if request.method == "POST":
        # Obtener los datos del formulario
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Validar que ambas contraseñas coinciden
        if new_password != confirm_password:
            flash("Las contraseñas no coinciden. Por favor, inténtalo de nuevo.", "danger")
            return redirect(url_for("reset_password"))

        try:
            # Cambiar la contraseña en AD
            cambiar_contrasena_ad(
                AD_SERVER,
                AD_DOMAIN,
                AD_BASE_DN,
                session['username'],
                session['user_data']['password'],
                new_password
            )

            flash("Contraseña cambiada exitosamente. Por favor, inicia sesión nuevamente.", "success")

            # Cerrar la sesión del usuario para forzar a que vuelva a iniciar con la nueva contraseña
            session.clear()
            return redirect(url_for("login"))

        except Exception as e:
            flash(f"Error al cambiar la contraseña: {str(e)}", "danger")
            return redirect(url_for("reset_password"))
        
#Creación usuarios
@app.route("/user/new", methods=["GET", "POST"])
def new_user():
    if 'username' not in session or not session.get('is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        try:
            # Recoge los datos del formulario
            user_data = {
                "username": request.form["username"],
                "password": request.form["password"],
                "givenName": request.form["givenName"],
                "sn": request.form["sn"],
                "grupo": request.form["grupo"],
                "mail": request.form["mail"],
                "UO" : request.form["UO"],
                "telephoneNumber": request.form["telephoneNumber"],
            }
            # Llamar a la función para crear el usuario
            crear_usuario_ad(
                AD_SERVER,
                AD_DOMAIN,
                AD_BASE_DN,
                session['username'],
                session['user_data']['password'],
                user_data
            )
            flash("Usuario creado exitosamente.", "success")
            print (user_data)
            return redirect(url_for("dashboard"))

        except Exception as e:
            flash(f"Error al crear el usuario: {str(e)}", "danger")
            return redirect(url_for("new_user"))

    return render_template("user_creacion.html", action="Crear")

#Edición Usuarios
@app.route("/user/edit/<username>", methods=["GET", "POST"])
def edit_user(username):
    # Verificar permisos
    if "username" not in session or not session.get("is_admin", False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))

    # Inicializar user_data
    user_data = {
        "givenName": "",
        "sn": "",
        "mail": "",
        "telephoneNumber": "",
        "distinguishedName": "",
    }

    if request.method == "GET":
        try:
            # Obtener detalles del usuario
            user_data = obtener_detalle_usuario2(
                AD_SERVER,
                AD_DOMAIN,
                AD_BASE_DN,
                session["username"],
                session["user_data"]["password"],
                username
            )
            if not user_data:
                flash("El usuario no fue encontrado.", "danger")
                return redirect(url_for("dashboard"))
        except Exception as e:
            flash(f"Error al obtener datos del usuario: {e}", "danger")
            return redirect(url_for("dashboard"))

        # Renderizar formulario con datos del usuario
        return render_template("user_edicion.html", user=user_data)

    if request.method == "POST":
        try:
            # Obtener datos del formulario
            givenName = request.form.get("givenName")
            sn = request.form.get("sn")
            mail = request.form.get("mail")
            telephoneNumber = request.form.get("telephoneNumber")
            distinguishedName = request.form.get("distinguishedName")

            if not givenName or not sn or not mail or not telephoneNumber or not distinguishedName:
                flash("Todos los campos son obligatorios, incluido el Distinguished Name.", "danger")
                return render_template("user_edicion.html", user=user_data)

            # Crear diccionario de atributos
            atributos = {
                "givenName": givenName,
                "sn": sn,
                "mail": mail,
                "telephoneNumber": telephoneNumber,
                "distinguishedName": distinguishedName,
            }

            # Editar usuario en Active Directory
            exito = editar_usuario_ad(
                AD_SERVER,
                AD_DOMAIN,
                AD_BASE_DN,
                session["username"],
                session["user_data"]["password"],
                atributos
            )

            if exito:
                flash("Usuario editado exitosamente.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("No se pudo editar el usuario. Verifica los datos.", "danger")

        except Exception as e:
            flash(f"Error al editar el usuario: {e}", "danger")
            print(f"Excepción al editar usuario: {e}")

        # Renderizar formulario con los datos actuales en caso de error
        return render_template("user_edicion.html", user=user_data)

#Eliminación usuarios
@app.route("/user/delete/<username>")
def delete_user(username):
    if 'username' not in session or not session.get('is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))

    try:
        # Verifica que la contraseña está presente
        if 'password' not in session['user_data']:
            flash("Contraseña no encontrada en la sesión. Por favor, inicia sesión nuevamente.", "danger")
            return redirect(url_for("logout"))

        # Elimina el usuario
        eliminar_usuario_ad(
            AD_SERVER,
            AD_DOMAIN,
            AD_BASE_DN,
            session['username'],  # Usuario actual
            session['user_data']['password'],  # Contraseña desde la sesión
            username
        )
        flash(f"Usuario {username} eliminado exitosamente.", "success")
    except Exception as e:
        flash(f"Error al eliminar el usuario: {str(e)}", "danger")

    return redirect(url_for("user"))

#Info usuario
@app.route("/user/<username>")
def user_detail(username):
    if 'username' not in session:
        flash("Debes iniciar sesión primero.", "danger")
        return redirect(url_for("login"))

    try:
        print(f"Intentando obtener detalles para el usuario: {username}")

        # Llamar a la función para obtener detalles del usuario
        user_data, error = obtener_detalle_usuario(
            AD_SERVER, 
            AD_DOMAIN, 
            AD_BASE_DN, 
            session['username'], 
            session['user_data']['password'], 
            username
        )

        if error:
            print(f"Error devuelto: {error}")
            flash(error, "warning")
            return redirect(url_for("dashboard"))

        print(f"Datos del usuario obtenidos: {user_data}")

        return render_template("user_details.html", user=user_data)

    except Exception as e:
        print(f"Excepción al obtener datos del usuario: {e}")
        flash(f"Error al obtener datos del usuario: {e}", "danger")
        return redirect(url_for("dashboard"))

#Info equipo
@app.route("/computer/<cn>")
def computer_detail(cn):
    if 'username' not in session:
        flash("Debes iniciar sesión primero.", "danger")
        return redirect(url_for("login"))

    try:
        print(f"Intentando obtener detalles para el usuario: {cn}")

        # Llamar a la función para obtener detalles del usuario
        computer_data, error = obtener_detalle_equipo(
            AD_SERVER, 
            AD_DOMAIN, 
            AD_BASE_DN_EQUIPOS, 
            session['username'], 
            session['user_data']['password'], 
            cn
        )
        if not computer_data:
            print(f"Error devuelto: {error}")
            flash(error, "warning")
            return redirect(url_for("dashboard"))


        print(f"Datos del equipo obtenidos: {computer_data}")

        return render_template("computer_details.html", computer=computer_data)

    except Exception as e:
        print(f"Excepción al obtener datos del equipo: {e}")
        flash(f"Error al obtener datos del equipo: {e}", "danger")
        return redirect(url_for("dashboard"))

#Info grupo
@app.route("/group/<cn>")
def group_detail(cn):
    if 'username' not in session:
        flash("Debes iniciar sesión primero.", "danger")
        return redirect(url_for("login"))

    try:
        print(f"Intentando obtener detalles para el grupo: {cn}")

        # Llamar a la función para obtener detalles del grupo
        group_data, error = obtener_detalle_grupo(
            AD_SERVER, 
            AD_DOMAIN, 
            AD_BASE_DN, 
            session['username'], 
            session['user_data']['password'], 
            cn
        )
        if not group_data:
            print(f"Error devuelto: {error}")
            flash(error, "warning")
            return redirect(url_for("dashboard"))


        print(f"Datos del grupo obtenidos: {group_data}")

        return render_template("group_details.html", group=group_data)

    except Exception as e:
        print(f"Excepción al obtener datos del grupo: {e}")
        flash(f"Error al obtener datos del grupo: {e}", "danger")
        return redirect(url_for("dashboard"))

#Info GPO      
@app.route("/gpo/<cn>")
def gpo_detail(cn):
    if 'username' not in session:
        flash("Debes iniciar sesión primero.", "danger")
        return redirect(url_for("login"))

    try:
        print(f"Intentando obtener detalles para la GPO: {cn}")

        # Llamar a la función para obtener detalles de la GPO
        gpo_data, error = obtener_detalle_gpo(
            AD_SERVER,
            AD_DOMAIN,
            AD_BASE_GPO ,
            session['username'],
            session['user_data']['password'],
            cn
        )
        if not gpo_data:
            print(f"Error devuelto: {error}")
            flash(error, "warning")
            return redirect(url_for("dashboard"))

        print(f"Datos de la GPO obtenidos: {gpo_data}")
        return render_template("gpo_details.html", gpo=gpo_data)

    except Exception as e:
        print(f"Excepción al obtener datos de la GPO: {e}")
        flash(f"Error al obtener datos de la GPO: {e}", "danger")
        return redirect(url_for("dashboard"))

#Creación grupos
@app.route("/group/new", methods=["GET", "POST"])
def new_group():
    if 'username' not in session or not session.get('is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        try:
            # Recoge los datos del formulario
            user_data = {
                "group_name": request.form["group_name"],
                "descripcion": request.form["descripcion"],
                "grupos_superiores": request.form["grupos_superiores"],
                "miembros": request.form["miembros"],
                #"mail": request.form["mail"],
                "UO" : request.form["UO"]
            }
            # Llamar a la función para crear el usuario
            crear_grupo_ad(
                AD_SERVER,
                AD_DOMAIN,
                AD_BASE_DN,
                session['username'],
                session['user_data']['password'],
                user_data
            )
            flash("Grupo creado exitosamente.", "success")
            print (user_data)
            return redirect(url_for("dashboard"))

        except Exception as e:
            flash(f"Error al crear el grupo: {str(e)}", "danger")
            return redirect(url_for("dashboard"))

    return render_template("group_creacion.html", action="Crear")

#Eliminación grupos
@app.route("/grupo/delete/<cn>")
def delete_group(cn):
    if 'username' not in session or not session.get('is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))

    try:
        # Elimina el grupo
        eliminar_grupos_ad(
            AD_SERVER,
            AD_DOMAIN,
            AD_BASE_DN,
            session['username'],  # Usuario actual
            session['user_data']['password'],  # Contraseña desde la sesión
            cn
        )
        flash(f"Grupo {cn} eliminado exitosamente.", "success")
    except Exception as e:
        flash(f"Error al eliminar el grupo: {str(e)}", "danger")

    return redirect(url_for("grupo"))

if __name__ == "__main__":
    app.run(debug=True)
