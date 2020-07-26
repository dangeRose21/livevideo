from sys import stdout
from makeup_artist import Makeup_artist
import logging
from flask import Flask, render_template, Response, jsonify, redirect, session, url_for
from flask_socketio import SocketIO
from camera import Camera
from utils import base64_to_pil_image, pil_image_to_base64

##auth
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode


app = Flask(__name__)

##auth
oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id='Z8TLBSPmN3P0GsNeUWRPh0PXVft1PjLx',
    client_secret='YeH8BIwDQcYWvolyZX83qOIe0q7S5ctbtR5GnDFiNhH0vM8JHNujpEHWoaacpQEB',
    api_base_url='https://dev-upklm0gs.us.auth0.com',
    access_token_url='https://dev-upklm0gs.us.auth0.com/oauth/token',
    authorize_url='https://dev-upklm0gs.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

app.logger.addHandler(logging.StreamHandler(stdout))
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True
socketio = SocketIO(app)
camera = Camera(Makeup_artist())

##callback for auth
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.jason()

    #Store the user information in flask sess
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/temp')

@app.route('/')
def login():
    return auth0.authorize_redirect(redirect_uri='https://livevideofeed.herokuapp.com/temp')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

@socketio.on('input image', namespace='/test')
def test_message(input):
    input = input.split(",")[1]
    camera.enqueue_input(input)
    #camera.enqueue_input(base64_to_pil_image(input))


@socketio.on('connect', namespace='/test')
def test_connect():
    app.logger.info("client connected")

@app.route('/live')
def livefeed():
    """Video streaming home page."""
    return render_template('live.html')

@app.route('/temp')
def temp():
    return render_template('temp.html')

@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': 'Z8TLBSPmN3P0GsNeUWRPh0PXVft1PjLx'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

def gen():
    """Video streaming generator function."""

    app.logger.info("starting to generate frames!")
    while True:
        frame = camera.get_frame() #pil_image_to_base64(camera.get_frame())
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


@app.route('/video_feed')
def video_feed():
    """Video streaming route. Put this in the src attribute of an img tag."""
    return Response(gen(), mimetype='multipart/x-mixed-replace; boundary=frame')


if __name__ == '__main__':
    socketio.run(app)
