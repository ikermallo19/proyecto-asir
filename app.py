from flask import Flask, render_template, request, redirect, url_for, flash, session
from funcionesLdap import iniciar_sesion_ad, crear_usuario_ad, editar_usuario_ad, eliminar_usuario_ad, obtener_usuarios_ad, obtener_detalle_usuario, crear_grupo_ad, obtener_gpos, obtener_grupos, obtener_equipos, obtener_detalle_equipo
import logging

app = Flask(__name__)
app.secret_key = 'secret_key'

logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

# Configuración del servidor Active Directory
AD_SERVER = 'ldaps://leon.datanet.local'    #Servidor Active Directory
AD_DOMAIN = 'datanet.local'                 #Dominio
AD_BASE_DN = 'ou=USUARIOS,ou=DATANET,dc=datanet,dc=local'   #Ruta busqueda usuarios
AD_BASE_DN_EQUIPOS = 'ou=EQUIPOS,ou=DATANET,dc=datanet,dc=local'   #Ruta busqueda usuarios
AD_BASE_GPO = 'CN=Policies,CN=System,DC=datanet,DC=local'

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
    grupos = obtener_grupos(AD_SERVER, AD_DOMAIN, AD_BASE_DN_EQUIPOS)
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
    try:
        with open('app.log', 'r') as log:
            log_contents = log.readlines()
    except FileNotFoundError:
        log_contents = ["Log file not found."]
    return render_template('logs.html',logs=log_contents)

#Pantalla Equipos
@app.route("/computer")
def computer():
    if 'username' not in session:
        return redirect(url_for("login"))
    
    is_admin = session.get('is_admin', False)
    computers = obtener_equipos(AD_SERVER, AD_DOMAIN, AD_BASE_DN_EQUIPOS)
    return render_template("computer.html", username=session['username'], is_admin=is_admin, computers=computers)


#Creación usuarios -- SOLO QUEDA GRUPOS
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
                "UO" : request.form["UO"]
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
    if 'username' not in session or not session.get('is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        try:
            user_data, error = obtener_detalle_usuario(
                AD_SERVER, 
                AD_DOMAIN, 
                AD_BASE_DN, 
                session['username'], 
                session['user_data']['password'], 
                username
            )
        
            #Datos formulario
            dn = request.form.get('dn')
            givenName = request.form.get('givenName')
            sn = request.form.get('sn')
            mail = request.form.get('mail')
            telephoneNumber = request.form.get('telephoneNumber')
            #print(f"Valor de user['cn']: {user_data.get('cn')}")
            atributos = {
                'givenName': givenName,
                'sn': sn,
                'mail': mail,
                'telephoneNumber': telephoneNumber
            }

            editar_usuario_ad(
                AD_SERVER,
                AD_DOMAIN, 
                AD_BASE_DN,
                session['username'],
                session['user_data']['password'],
                atributos
            )
            flash("Usuario editado exitosamente.", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            print(f"Excepción al obtener datos del usuario: {e}")
            flash(f"Error al obtener datos del usuario: {e}", "danger")
            return redirect(url_for("dashboard"))

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

#Info grupo
@app.route("/computer/<cn>")
def computer_detail(cn):
    if 'username' not in session:
        flash("Debes iniciar sesión primero.", "danger")
        return redirect(url_for("login"))

    try:
        print(f"Intentando obtener detalles para el usuario: {cn}")

        # Llamar a la función para obtener detalles del usuario
        user_data, error = obtener_detalle_equipo(
            AD_SERVER, 
            AD_DOMAIN, 
            AD_BASE_DN, 
            session['username'], 
            session['user_data']['password'], 
            cn
        )
        if not user_data[cn]:
            print(f"Error devuelto: {error}")
            flash(error, "warning")
            return redirect(url_for("dashboard"))

        print(f"Datos del usuario obtenidos: {user_data}")

        return render_template("computer_details.html", user=user_data)

    except Exception as e:
        print(f"Excepción al obtener datos del usuario: {e}")
        flash(f"Error al obtener datos del usuario: {e}", "danger")
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

if __name__ == "__main__":
    app.run(debug=True)
