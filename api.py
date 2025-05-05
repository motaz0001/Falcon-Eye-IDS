from flask import Flask, request, redirect, url_for, session, jsonify, send_file
from flask_cors import CORS
import pandas as pd
from datetime import date,timedelta
import os
from flask_session import Session

app = Flask(__name__)
CORS(app, origins='*', methods=['GET'], allow_headers=['Content-Type'], supports_credentials=True)
app.secret_key = 'put_your_secret_key' 
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
Session(app)
log_dir=r'\logs' 
alert_file= log_dir + '\\' + str(date.today()) + "\\alerts.csv"
traffic_file= log_dir + '\\' + str(date.today()) + "\\traffic.csv"
files_list= {}

users = {} #add your users here as key and password as value e.g. {'admin':'admin'}


@app.route('/login', methods=['get'])
def login():
    session.permanent = True
    username = request.args.get('username')
    password = request.args.get('password')
    if username in users and password == users[username]:
        session['username'] = username
        return 'Seccess', 200
    return 'Unauthorized', 401

@app.route('/logout')
def logout():
    session.pop('username', None)
    return 'Seccess', 200

@app.route('/traffic', methods=['GET'])
def get_traffic():
    if 'username' in session:
        df = pd.read_csv(traffic_file)
        data = df.to_dict(orient='records')
        return jsonify(data)
    return 'Unauthorized', 401

@app.route('/alerts', methods=['GET'])
def get_alerts():
    if 'username' in session:
        df = pd.read_csv(alert_file)
        data = df.to_dict(orient='records')
        return jsonify(data)
    return 'Unauthorized', 401

@app.route('/logs', methods=['get'])
def get_logs():
    if 'username' in session:
        for root, dirs, files in os.walk(log_dir):
            for dir_name in dirs:
                path= log_dir + '\\' + dir_name
                files_list[dir_name]= os.listdir(path)
        return jsonify(files_list)
    return 'Unauthorized', 401

@app.route('/file', methods=['get'])
def get_file():
    if 'username' in session:
        if request.args.get('file_name') == None : return 'Invalid file name'
        get_logs()
        if len(request.args.get('file_name').split(r'\\')) < 2 : return 'Invalid format'
        dir_name=request.args.get('file_name').split(r'\\')[0]
        file_name=request.args.get('file_name').split(r'\\')[1]
        if dir_name not in files_list or file_name not in files_list[dir_name] : return 'Forbidden' , 403
        file_path= log_dir + '\\' + dir_name + '\\' + file_name
        return send_file(file_path, as_attachment=True, mimetype='text/csv')
    return 'Unauthorized', 401


app.run(host='0.0.0.0')
