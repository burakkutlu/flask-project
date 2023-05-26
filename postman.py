from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify


app = Flask(__name__)

@app.route('/', methods=["POST", "GET"])
def home():
    if request.method =="POST":
        print(request.form["username"])
        return request.form

    return "home page"

app.run(port=5001)