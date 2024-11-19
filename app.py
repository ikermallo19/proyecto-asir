from flask import Flask, render_template, request, redirect, url_for, flash, session
from funcionesLdap import iniciar_sesion_ad, crear_usuario_ad, editar_usuario_ad, eliminar_usuario_ad, obtener_usuarios_ad


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

        # Intentar iniciar sesión en el AD
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



#Botones a visualizar
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



if __name__ == "__main__":
    app.run(debug=True)
