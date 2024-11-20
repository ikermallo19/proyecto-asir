from flask import Flask, render_template, request, redirect, url_for, flash, session
from funcionesLdap import iniciar_sesion_ad, crear_usuario_ad, editar_usuario_ad, eliminar_usuario_ad, obtener_usuarios_ad, obtener_detalle_usuario
# import logging

# Configurar logging para ldap3
# logging.basicConfig(
#     filename='app.log',
#     level=logging.DEBUG,
#     format='%(asctime)s - %(levelname)s - %(message)s'
# )
app = Flask(__name__)
app.secret_key = 'secret_key'

# Configuración del servidor Active Directory
AD_SERVER = 'ldaps://leon.datanet.local'    #Servidor Active Directory
AD_DOMAIN = 'datanet.local'                 #Dominio
AD_BASE_DN = 'ou=USUARIOS,ou=DATANET,dc=datanet,dc=local'   #Ruta usuario


#Iniciar sesión
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Intentamos iniciar sesión en el AD
        user_data, error = iniciar_sesion_ad(AD_SERVER, AD_DOMAIN, AD_BASE_DN, username, password)

        if error:
            flash(error, "danger")
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
    users = obtener_usuarios_ad(AD_SERVER, AD_DOMAIN, AD_BASE_DN)

    return render_template("dashboard.html", username=session['username'], is_admin=is_admin, users=users)



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
                "sn": request.form["sn"]
            }
            #print (user_data);
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
            return redirect(url_for("dashboard"))

        except Exception as e:
            flash(f"Error al crear el usuario: {str(e)}", "danger")
            return redirect(url_for("new_user"))

    return render_template("user_form.html", action="Crear")




#Edición Usuarios
@app.route("/user/edit/<username>", methods=["GET", "POST"])
def edit_user(username):
    if 'username' not in session or not session.get('is_admin', False):
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        user_data = {
            "givenName": request.form["givenName"],
            "sn": request.form["sn"]
        }
        editar_usuario_ad(AD_SERVER, AD_DOMAIN, AD_BASE_DN, session['username'], session['user_data']['password'], username, user_data)
        flash("Usuario editado exitosamente.", "success")
        return redirect(url_for("dashboard"))

    return render_template("user_form.html", action="Editar")



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

    return redirect(url_for("dashboard"))


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


if __name__ == "__main__":
    app.run(debug=True)
