
# Department Management System

## Table of Contents:
1. **Introduction**
2. **Features**
3. **Installation**
4. **Usage**
5. **Directory Structure**
6. **Models**
7. **Views**
8. **Templates**
9. **Routes**
10. **Contributing**
11. **License**

---

### 1. Introduction
This Django-based Department Management System allows users to create, view, update, and delete (soft-delete) department records. The application is designed with a responsive user interface and follows the Model-View-Template (MVT) pattern.

---

### 2. Features
- **CRUD Operations:** Add, view, update, and delete department records.
- **Soft Deletion:** Departments are marked inactive instead of permanently deleted.
- **Responsive Design:** Works on both mobile and desktop devices.
- **Separation of Concerns:** Modular code with a `base.html` template for consistent UI.
  
---

### 3. Installation

1. **Clone the Repository:**
   ```bash
   git clone <repository_url>
   cd department_management
   ```

2. **Create a Virtual Environment:**
   ```bash
   python -m venv env
   source env/bin/activate   # On Windows use `env\Scripts\activate`
   ```

3. **Install Dependencies:**
   ```bash
   pip install django
   ```

4. **Migrate the Database:**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Run the Development Server:**
   ```bash
   python manage.py runserver
   ```

6. **Access the Application:**
   Open your browser and navigate to [http://localhost:8000/](http://localhost:8000/)

---

### 4. Usage
- **View Departments:** Default route (`/`).
- **Add Department:** Navigate to `/adddepart`.
- **Update Department:** Click "Edit" on any department row.
- **Delete Department:** Click "Delete" on any department row.

---

### 5. Directory Structure
```plaintext
deptapp/
├── migrations/          # Database migrations
├── static/
│   └── css/
│       └── style.css    # Centralized CSS file
├── templates/
│   ├── base.html        # Base template
│   ├── index.html       # Home view
│   ├── adddepart.html   # Add department form
│   └── updatedepart.html # Update department form
├── __init__.py
├── admin.py
├── apps.py
├── models.py            # Department model
├── tests.py
├── urls.py              # URL routing
└── views.py             # Controller logic
```

---

### 6. Models (`models.py`)
**Depart Model:**
- `dept_id` - Auto-incrementing primary key.
- `depart_name` - Department's name (max length: 100).
- `description` - Description (max length: 300).
- `created_at` - Timestamp for record creation.
- `updated_at` - Timestamp for last update.
- `status` - Boolean for soft-deletion control.

---

### 7. Views (`views.py`)
- **`showHome`**: Displays active departments.
- **`modifyDepart`**: Provides data for modifying departments.
- **`addDepart`**: Handles the creation of a new department.
- **`Deletedepart`**: Soft-deletes a department by setting `status` to `False`.
- **`Updatedepart`**: Handles department updates.

---

### 8. Templates
- **base.html**: Base structure with sidebar navigation and dynamic content block.
- **index.html**: Displays the list of departments.
- **adddepart.html**: Form to create a new department.
- **updatedepart.html**: Form to update an existing department.

---

### 9. Routes (`urls.py`)
| URL Path            | View Function      | Description                          |
|---------------------|--------------------|--------------------------------------|
| `/`                 | `showHome`         | View all active departments          |
| `/modifydepart`     | `modifyDepart`     | Modify department information        |
| `/adddepart`        | `addDepart`        | Create a new department              |
| `/delete/<int:id>`  | `Deletedepart`     | Soft delete a department by `id`     |
| `/update/<int:id>`  | `Updatedepart`     | Update a department by `id`          |

---

### 10. Contributing
Contributions are welcome! Please submit a pull request or open an issue if you encounter any problems.

---

### 11. License
This project is licensed under the MIT License. 

---

### Contact
For any questions or feedback, please reach out at charudattpalvi@gmail.com.
