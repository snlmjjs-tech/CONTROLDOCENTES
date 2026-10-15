# Puesta en marcha con Supabase

1. **Crear el proyecto** en supabase.com. Recomendado en "Security": dejar *Enable Data API* marcado y **desmarcar** *Automatically expose new tables* (el SQL ya da los permisos necesarios).
2. **Crear las tablas:** SQL Editor → pegar todo `supabase/schema.sql` → Run.
3. **Cerrar el registro público:** Authentication → Sign In / Providers → desactivar *Allow new users to sign up*.
4. **Crear usuarios:** Authentication → Users → *Add user* (marcar *Auto Confirm User*): una cuenta por inspector (3) y una para el kiosco.
5. **Asignar roles:** SQL Editor, cambiando correos y nombres:
   ```sql
   insert into public.usuarios (user_id, nombre, rol)
   select id, 'Nombre Inspector', 'inspector' from auth.users where email = 'inspector1@ejemplo.cl';
   insert into public.usuarios (user_id, nombre, rol)
   select id, 'Kiosco', 'kiosco' from auth.users where email = 'kiosco@ejemplo.cl';
   ```
6. **Conectar la página:** Project Settings → API → copiar *Project URL* y la clave *anon public* en las dos constantes `SUPABASE_URL` y `SUPABASE_KEY` al inicio del último `<script>` de `index.html`. (Nunca usar la clave `service_role`.)
7. Abrir `index.html` en el computador del kiosco, iniciar sesión con la cuenta del kiosco (queda recordada), y cargar los funcionarios desde Administración → Funcionarios.

Cada inspector entra a Administración con su correo y contraseña. La pestaña **Auditoría** muestra quién creó, cambió o eliminó cada registro.
