from fastapi.templating import Jinja2Templates

# Support nested template folders (auth, users, etc.)
templates = Jinja2Templates(directory="app/templates")
