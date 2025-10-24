# Porinity Matrimony Platform (Server)

**Live Server:** [https://porinity-server.vercel.app/](https://porinity-server.vercel.app/)



---

## 🌟 Features

1. **JWT Authentication**: Secure login, registration, and protected routes using HTTP-only cookies.
2. **Responsive CORS**: Cross-origin requests supported for both local and deployed frontends.
3. **User Registration & Login**: Email/password and Google sign-in supported (see client).
4. **Biodata Management**: Create, edit, view, and filter biodata with auto-generated IDs.
5. **Premium Membership**: Users can request premium status and admins can approve.
6. **Contact Requests**: Users can request contact info (with payment), admins approve.
7. **Favorites**: Add/remove biodata to favorites, view all favorites in dashboard.
8. **Success Stories**: Users can submit marriage stories, admins approve and feature them.
9. **Admin Dashboard**: Manage users, premium requests, contact requests, and success stories.
10. **Pagination & Filtering**: Biodata endpoints support pagination, filtering, and sorting.
11. **Environment Variables**: All secrets and credentials are hidden using `.env`.
12. **Notifications**: All CRUD/auth actions return clear JSON for toast/alert integration.

---

## 📦 API Endpoints

### Auth
- `POST /jwt` — Login, issues JWT tokens (sets cookies)
- `POST /refresh` — Refreshes access token using refresh token
- `POST /logout` — Logs out, clears cookies

### Users
- `POST /register` — Register a new user
- `GET /users/:uid` — Get user by UID
- `PUT /users/profile` — Update user profile (protected)
- `POST /users/profile` — Create/update user profile (protected)
- `POST /users/premium-request` — Request premium user status (protected)

### Biodata
- `GET /biodata` — List all biodata (pagination/filtering)
- `GET /biodata/premium` — List premium biodata
- `GET /biodata/:id` — Get biodata by ID
- `GET /biodata/user/:uid` — Get biodata by user UID (protected)
- `POST /biodata` — Create or update biodata (protected)
- `POST /biodata/:id/premium-request` — Request premium for a biodata (protected)

### Favorites
- `POST /favorites` — Add biodata to favorites (protected)
- `GET /favorites/:uid` — Get all favorite biodata for a user (protected)
- `DELETE /favorites` — Remove biodata from favorites (protected)

### Contact Requests
- `POST /contact-requests` — Request contact info (protected)
- `GET /contact-requests` — List user's contact requests (protected)
- `DELETE /contact-requests/:id` — Delete a contact request (protected)

### Success Stories
- `GET /success-stories` — List all approved success stories
- `POST /success-stories` — Submit a new success story

### Admin (all protected, admin only)
- `GET /admin/overview` — Dashboard stats & revenue
- `GET /admin/users` — List/search users
- `POST /admin/users/:uid/make-admin` — Promote user to admin
- `POST /admin/users/:uid/make-premium` — Promote user to premium
- `GET /admin/premium-requests` — List pending premium biodata requests
- `GET /admin/premium-user-requests` — List pending premium user requests
- `POST /admin/premium-user-requests/:uid/approve` — Approve premium user
- `POST /admin/premium-requests/:biodataId/approve` — Approve premium biodata
- `GET /admin/contact-requests` — List contact requests
- `POST /admin/contact-requests/:id/approve` — Approve contact request
- `GET /admin/success-stories` — List all success stories
- `PATCH /admin/success-stories/:id/status` — Update success story status
- `GET /admin/contact-messages` — List contact messages
- `PATCH /admin/contact-messages/:id` — Update contact message status

---

## 🚀 How to Run Locally

1. Clone the repo and `cd porinity-server`
2. Create a `.env` file with your MongoDB credentials and secrets:
   ```env
   DB_USER=your_db_user
   DB_PASS=your_db_pass
   ACCESS_TOKEN_SECRET=your_access_secret
   REFRESH_TOKEN_SECRET=your_refresh_secret
   CLIENT_URL=http://localhost:5173
   ADMIN_URL=http://localhost:5173
   ```
3. Run `npm install`
4. Run `npm start` or `nodemon index.js`

---

## 🔒 Environment Variables
- All sensitive keys (MongoDB, JWT, client URLs) are stored in `.env` and never committed.

---

## 📱 Responsiveness
- All endpoints and features are designed to support a fully responsive client (mobile, tablet, desktop).

---

**Enjoy building and exploring Porinity!**
