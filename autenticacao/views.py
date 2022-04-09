from django.shortcuts import render, redirect
from flask import request
from django.contrib.auth.models import User 
from django.http import HttpResponse
from django.contrib import messages, auth
from django.contrib.messages import constants

def home(request):
    return render(request, 'home.html')   

def cadastro(request):
    if request.method == 'GET':
        return render(request, 'cadastro.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')
        user = User.objects.filter(username = username)
        if user.exists():
            messages.add_message(request, constants.ERROR,"Usuário já existe!")
            return redirect('/auth/cadastro')
        if not password == confirm_password:
            messages.add_message(request, constants.ERROR, "Senhas não coincidem!")
            return redirect('/auth/cadastro')
        elif len(username.strip()) == 0 or len(password.strip()) == 0 :
            messages.add_message(request, constants.ERROR,"Preencha os campos antes de continuar!")
            return redirect('/auth/cadastro')
        try:
            user = User.objects.create_user(username=username,
            password=password)
            user.save()
            messages.add_message(request, constants.SUCCESS, 'Usuário criado com sucesso!')
            return redirect('/auth/login')
        except:
            messages.add_message(request, constants.ERROR, 'Erro interno do sistema')
            return redirect('/auth/cadastro')


def login(request):
    if request.method == "GET":
        return render(request, 'login.html')
    elif request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        usuario = auth.authenticate(username=username, password=password)
        if not usuario:
            messages.add_message(request, constants.ERROR, 'Usuário ou senha inválidos!')
            return redirect('/auth/login')
        else:
            auth.login(request,usuario)
            return redirect("/home")

def sair(request):
    auth.logout(request)