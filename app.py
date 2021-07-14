import uuid
import requests
from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_session import Session
import msal
import config

app = Flask(__name__)
app.config.from_object(config)
Session(app)

@app.route("/")
def index():
    if not session.get("user"):
        session["state"] = str(uuid.uuid4())
        auth_url = _build_auth_url(scopes=config.SCOPE, state=session["state"])
        return redirect(auth_url, code=302)
    user_name=session["user"]["name"]
    email=session["user"]["preferred_username"] 
    token = _get_token_from_cache(config.SCOPE)
    #userdata = requests.get('https://graph.microsoft.com/v1.0/me', headers={'Authorization': 'Bearer ' + token['access_token']}).json()
    #check_admin = requests.post('https://graph.microsoft.com/v1.0/me/checkMemberGroups', headers={'Authorization': 'Bearer ' + token['access_token']}, json={'groupIds':["61777084-203c-4ce9-998a-39ab61852bb8"]}).json()
   # return render_template('index.html', user=session["user"], data=userdata, data2=check_admin)
    return render_template('index.html', user_name=user_name, email=email)

@app.route('/unauthorized')
def unauthorized():
	return render_template('unauthorized.html')
    
@app.route('/ansiblelaunch', methods=['POST'])
def ansiblelaunch():
    if request.method == 'POST':
	    if 'ansiblelaunch' in request.form:
	        response = requests.post("https://tower.na.xom.com/api/v2/job_templates/10682/launch/",  #change
	        headers={"content-type": "application/json",
	                "Authorization": "Bearer n4pvI9BgVr6CL6g3VN3LyxTN89B9DW"}, #change
	                verify=False,
	                json={"extra_vars":
                            {
                            "operation": request.form['operation'],
                            "customer": request.form['customer'],
                            "email": request.form['email'],
                            "cluster_name": request.form['cluster_name'],
                            "nodea_name": request.form['nodea_name'],
                            "nodeb_name": request.form['nodeb_name'],
                            "vlan_number": request.form['vlan_number'],
                            "lifa_address": request.form['lifa_address'],
                            "lifb_address": request.form['lifb_address'],
                            "lif_icla_address": request.form['lif_icla_address'],
                            "lif_iclb_address": request.form['lif_iclb_address'],
                            "vlanicl_number": request.form['vlanicl_number'],
                            "lif_netmask": request.form['lif_netmask'],
                            "failover_group": request.form['failover_group'],
                            "lificl_netmask": request.form['lificl_netmask'],
                            "failovericl_group": request.form['failovericl_group'],
                            "svm1_name": request.form['svm1_name'],
                            "lif_svm1a_address": request.form['lif_svm1a_address'],
                            "lif_svm1b_address": request.form['lif_svm1b_address'],
                            "diska_type": request.form['diska_type'],
                            "diska_count": request.form['diska_count'],
                            "diskb_count": request.form['diskb_count'],
                            "aggregatea_name": request.form['aggregatea_name'],
                            "aggregateb_name": request.form['aggregateb_name'], 
                            "porta": request.form['porta'], 
                            "portb": request.form['portb'], 
                            "portc": request.form['portc'], 
                            "portd": request.form['portd'], 
                            "porte": request.form['porte'], 
                            "portf": request.form['portf'], 
                            "portg": request.form['portg'], 
                            "porth": request.form['porth'],             
	                        }
	                    }
	                    )                             
	        data = response.json()
	        jobid = data.get("job")
	        if jobid:
	            flash('Request Submitted Successfully', 'success')
	            return redirect("/")
    return render_template('index.html')

@app.route("/login")
def login():
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=config.SCOPE, state=session["state"])
    return render_template("login.html", auth_url=auth_url)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

@app.route(config.REDIRECT_PATH)
def authorized():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("index"))
    if "error" in request.args:
        return render_template("unauthorized.html", result=request.args)
    if request.args.get('code'):
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=config.SCOPE,
            redirect_uri=url_for("authorized", _scheme='https', _external=True))
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    return redirect(url_for("index"))

def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        config.CLIENT_ID, authority=authority or config.AUTHORITY,
        client_credential=config.CLIENT_SECRET, token_cache=cache)

def _build_auth_url(authority=None, scopes=None, state=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for("authorized", _scheme='https', _external=True))

def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result

app.jinja_env.globals.update(_build_auth_url=_build_auth_url)  # Used in template

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)