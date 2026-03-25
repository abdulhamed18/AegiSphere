from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import redirect, render
from django.urls import reverse


def register(request):
    """
    User registration view for AegiSphere.

    Uses Django's built-in UserCreationForm and renders the
    templates/registration/register.html template.
    """
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect(reverse("login"))
    else:
        form = UserCreationForm()

    return render(request, "registration/register.html", {"form": form})

