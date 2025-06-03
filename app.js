const pool = require('./dbPool.js');
const express = require ("express")
const mysql2 = require ("mysql2")
const session = require ("express-session")
const bodyParser = require ('body-parser')
const path = require ("path")
const bcrypt = require("bcrypt");

const PORT = 3000
const app = express()


const urlencodedParser = express.urlencoded({extended: false});

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));   
// После создания app, до любых res.render:
app.set("views", path.join(__dirname, "views"));
app.engine("html", require("ejs").renderFile);
app.set("view engine", "html");

app.get('/', (req, res) => {
    const error      = req.query.error      || null;
    const registered = req.query.registered || null;
    res.render('auth', { error, registered });
});

app.get('/lost_pass', (req, res) => {
  // считываем флаги из query-строки, по-умолчанию null
  const error   = req.query.error   || null;
  const success = req.query.success || null;
  // рендерим lost_pass.html, передавая обе переменные
  res.render('lost_pass', { error, success });
});

// Проверка, что пользователь авторизован
function authRequired(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    res.redirect('/');
}

// Получение формы Мои тренировки
app.get('/routines', authRequired, (req, res) => {
    const userId = req.session.user.id;
    const sql = `
    SELECT
        w.id_w            AS workout_id,
        w.title           AS workout_name,
        w.created_at      AS workout_date,
        e.id_exrc         AS exrc_id,
        e.name_exrc       AS exrc_name
    FROM user_workouts uw
    JOIN workouts w             ON uw.workout_id = w.id_w
    LEFT JOIN workout_exercises we ON w.id_w      = we.id_workout
    LEFT JOIN exercises e        ON we.id_exercise = e.id_exrc
    WHERE uw.user_id = ?
    ORDER BY w.created_at DESC, w.id_w, we.display_order
    `;

    pool.query(sql, [userId], (err, rows) => {
        if (err) {
        console.error('Error fetching user routines:', err);
        return res.status(500).send('Ошибка при получении списка тренировок');
        }

        // Группируем по workout_id
        const map = {};
        rows.forEach(row => {
        const wid = row.workout_id;
        if (!map[wid]) {
            map[wid] = {
            id: wid,
            name: row.workout_name,
            date: row.workout_date,
            exercises: []
            };
        }
        if (row.exrc_id && row.exrc_name) {
            map[wid].exercises.push({
            id_exrc: row.exrc_id,
            name_exrc: row.exrc_name
            });
        }
    });
    const workouts = Object.values(map);
    res.render('routines', { workouts });
    });
});

// GET /add_routine — создание новой тренировки или редактирование существующей
app.get('/add_routine', authRequired, (req, res) => {
  const workoutId = parseInt(req.query.workout_id, 10);

  // 1) Тянем список всех упражнений (во всех случаях)
  pool.query(
    'SELECT id_exrc, name_exrc FROM exercises ORDER BY name_exrc',
    (exErr, exRows) => {
      if (exErr) {
        console.error('Error loading exercises:', exErr);
        return res.status(500).send('Ошибка при загрузке формы');
      }

      // Если нет workout_id – возвращаем форму «новая тренировка»
      if (!workoutId) {
        return res.render('add_routine', {
          exercises: exRows,
          workoutData: null
        });
      }

      // Иначе: редактирование. Проверяем, что текущий пользователь владеет этой тренировкой
      const userId = req.session.user.id;
      pool.query(
        'SELECT id FROM user_workouts WHERE user_id = ? AND workout_id = ?',
        [userId, workoutId],
        (uwErr, uwRows) => {
          if (uwErr) {
            console.error('DB error checking auth:', uwErr);
            return res.status(500).send('Ошибка сервера');
          }
          if (uwRows.length === 0) {
            return res.status(403).send('Нет доступа');
          }

          // 2) Берём title и дату
          pool.query(
            'SELECT title, DATE_FORMAT(created_at, "%Y-%m-%d") AS created_at FROM workouts WHERE id_w = ?',
            [workoutId],
            (wErr, wRows) => {
              if (wErr || wRows.length === 0) {
                console.error('Error loading workout data:', wErr);
                return res.status(500).send('Ошибка при получении данных тренировки');
              }
              const workoutInfo = wRows[0];

              // 3) Тянем все упражнения + нагрузки для этой тренировки
              const sql = `
                SELECT 
                  we.id_wrkt_exrc       AS wrkt_exrc_id,
                  we.id_exercise        AS exercise_id,
                  we.display_order      AS display_order,
                  esb.id_set_base       AS base_id,
                  esb.id_load_type      AS load_type_id,
                  wswr.reps             AS reps,
                  wswt.weight           AS weight,
                  wswt.duration_s       AS duration_s,
                  wstd.distance         AS distance
                FROM workout_exercises we
                JOIN exercise_set_base esb ON we.id_wrkt_exrc = esb.id_wrkt_exrc_set
                LEFT JOIN exercise_set_weight_reps wswr  ON esb.id_set_base = wswr.base_id
                LEFT JOIN exercise_set_weight_time wswt  ON esb.id_set_base = wswt.base_id
                LEFT JOIN exercise_set_reps wsrp          ON esb.id_set_base = wsrp.base_id
                LEFT JOIN exercise_set_distance_time wstd  ON esb.id_set_base = wstd.base_id
                LEFT JOIN exercise_set_time wst           ON esb.id_set_base = wst.base_id
                WHERE we.id_workout = ?
                ORDER BY we.display_order
              `;
              pool.query(sql, [workoutId], (weErr, weRows) => {
                if (weErr) {
                  console.error('Error loading exercises for edit:', weErr);
                  return res.status(500).send('Ошибка при получении упражнений');
                }

                // Формируем массив { wrkt_exrc_id, exercise_id, set_type, reps, weight, duration_s, distance }
                const workoutExercises = weRows.map(row => {
                  let setTypeCode = '';
                  let reps      = '';
                  let weight    = '';
                  let duration  = '';
                  let distance  = '';

                  switch (row.load_type_id) {
                    case 1: // weight_reps
                      setTypeCode = 'weight_reps';
                      reps    = row.reps;
                      weight  = row.weight;
                      break;
                    case 2: // weight_time
                      setTypeCode = 'weight_time';
                      weight  = row.weight;
                      duration = row.duration_s;
                      break;
                    case 3: // reps
                      setTypeCode = 'reps';
                      reps    = row.reps;
                      break;
                    case 4: // distance_time
                      setTypeCode = 'distance_time';
                      distance= row.distance;
                      duration= row.duration_s;
                      break;
                    case 5: // time
                      setTypeCode = 'time';
                      duration= row.duration_s;
                      break;
                    default:
                      setTypeCode = '';
                  }

                  return {
                    wrkt_exrc_id: row.wrkt_exrc_id,
                    exercise_id:    row.exercise_id,
                    set_type:       setTypeCode,
                    reps:           reps    != null ? reps.toString()     : '',
                    weight:         weight  != null ? weight.toString()   : '',
                    duration_s:     duration!= null ? duration.toString() : '',
                    distance:       distance!= null ? distance.toString() : ''
                  };
                });

                // Собираем итоговый workoutData
                const workoutData = {
                  id: workoutId,
                  title: workoutInfo.title,
                  created_at: workoutInfo.created_at,
                  exercises: workoutExercises
                };

                // Рендерим шаблон, передаём exercises + workoutData
                res.render('add_routine', {
                  exercises: exRows,
                  workoutData: workoutData
                });
              });
            }
          );
        }
      );
    }
  );
});


app.use(express.static(__dirname + "/public")); //обслуживание статических файлов из папки public

// АВТОРИЗАЦИЯ (гет)
app.get('/login', (req, res) => {
  const error      = req.query.error      || null;
  const registered = req.query.registered || null;
  res.render('auth', { error, registered });
});

// РЕГИСТРАЦИЯ (гет)
app.get("/reg", (req, res) => {
  // Собираем из query-параметров error и registered (если их нет — null)
    const error      = req.query.error      || null;
    const registered = req.query.registered || null;
    res.render("reg", { error, registered });
});

// Авторизация

app.post('/login', urlencodedParser, (req, res) => {
    const login = req.body.login;
    const pass  = req.body.pass;

    if (!login || !pass) { // 1) Проверка заполненности
        return res.redirect('/login?error=empty');
    }
    if (!login) {
        return res.redirect("/login?error=empty");
    }
    if (!pass) {
        return res.redirect("/login?error=empty");
    }

    pool.query( // 2) Достаем пользователя из БД по e-mail
        'SELECT id_user, pass_hash FROM users WHERE email = ?',
        [login],
        (dbErr, results) => {
        if (dbErr) {
            console.error('DB error during login:', dbErr);
            return res.render('auth.html', { error: 'server', registered: null });
        }

        if (results.length === 0) { // Пользователь с таким e-mail не найден
            return res.redirect('/login?error=invalid');
        }
        const user = results[0];

        bcrypt.compare(pass, user.pass_hash, (bcryptErr, isMatch) => { // 3) Сравниваем пароль с хэшем
            if (bcryptErr) {
            console.error('Bcrypt error during compare:', bcryptErr);
            return res.render('auth.html', { error: 'server', registered: null });
        }

        if (!isMatch) {
            // Пароль неверен
            return res.redirect('/login?error=invalid');
        }

        // 4) (Опционально) Проверяем подтверждение e-mail
        if (user.is_verified === 0) {
            return res.redirect('/login?error=unverified');
        }

        // 5) Успешная авторизация — сохраняем в сессии и редирект
        req.session.user = { id: user.id_user, email: login };
        res.redirect('/board');
        });
    }
);
});

// РЕГИСТРАЦИЯ

app.post("/reg", urlencodedParser, (req, res) => {
    const login = req.body.login;
    const pass  = req.body.pass;
  // 1. Проверка заполненности полей
    if (!login || !pass) {
        return res.redirect("/reg?error=empty");
    }

// 2. Проверяем, что e-mail ещё не занят
pool.query(
    "SELECT id_user FROM users WHERE email = ?",
    [login],
    (selectErr, rows) => {
    if (selectErr) {
        console.error("DB error on SELECT:", selectErr);
        return res.status(500).send("Internal Server Error");
    }
    if (rows.length > 0) {
        return res.redirect("/reg?error=duplicate");
    }

// 3. Хешируем пароль
bcrypt.hash(pass, 12, (hashErr, hash) => {
    if (hashErr) {
    console.error("Bcrypt error:", hashErr);
    return res.status(500).send("Internal Server Error");
    }

// 4. Вставляем нового пользователя
pool.query(
"INSERT INTO users (email, pass_hash) VALUES (?, ?)",
[login, hash],
(insertErr, result) => {
    if (insertErr) {
    console.error("DB error on INSERT:", insertErr);
    return res.status(500).send("Internal Server Error");
    }

    // 5. Редирект на форму логина с флагом успешной регистрации
    return res.redirect("/login?registered=1");
});
});
}
);
});

// ВОССТАНОВЛЕНИЕ ПАРОЛЯ

// POST /lost_pass — колбэк-стиль восстановления пароля
app.post('/lost_pass', urlencodedParser, (req, res) => {
  const login       = req.body.login;
  const pass        = req.body.pass;
  const passConfirm = req.body.pass_confirm;

  // 1) Проверяем, что все поля заполнены
  if (!login || !pass || !passConfirm) {
    return res.redirect('/lost_pass?error=empty');
  }
  // 2) Проверяем совпадение паролей
  if (pass !== passConfirm) {
    return res.redirect('/lost_pass?error=mismatch');
  }

  // 3) Проверяем, есть ли пользователь с таким e-mail
  pool.query(
    'SELECT id_user FROM users WHERE email = ?',
    [login],
    (selectErr, rows) => {
      if (selectErr) {
        console.error('DB error on SELECT for reset:', selectErr);
        return res.render('lost_pass', { error: 'server', success: null });
      }
      if (rows.length === 0) {
        return res.redirect('/lost_pass?error=notfound');
      }

      // 4) Хешируем новый пароль
      bcrypt.hash(pass, 12, (hashErr, hash) => {
        if (hashErr) {
          console.error('Bcrypt error hashing new password:', hashErr);
          return res.render('lost_pass', { error: 'server', success: null });
        }

        // 5) Обновляем пароль в БД
        pool.query(
          'UPDATE users SET pass_hash = ? WHERE email = ?',
          [hash, login],
          (updateErr) => {
            if (updateErr) {
              console.error('DB error on UPDATE password:', updateErr);
              return res.render('lost_pass', { error: 'server', success: null });
            }
            // 6) Успех!
            return res.redirect('/lost_pass?success=1');
          }
        );
      });
    }
  );
});


// защищённые страницы
app.get("/board", authRequired,   (req, res) => res.render("board.html"));
app.get("/map",   authRequired,   (req, res) => res.render("map.html"));
app.get("/profile", authRequired, (req, res) => res.render("profile.html"));
app.get("/settings",authRequired, (req, res) => res.render("settings.html"));
app.get("/lost_pass",(req, res) => res.render("lost_pass.html"));
app.get("/routines", authRequired, (req, res) => res.render("routines.html"));
app.get("/add_routine", authRequired, (req, res) => res.render("add_routine.html"));
app.get('/leave', (req, res) => {
    // Завершаем сессию пользователя
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Ошибка при выходе из системы');
        }
        // Перенаправляем на страницу логина после завершения сессии
        res.redirect('/login');
    });
});
app.get('/change_pass', (req, res) => {
    // Проверяем, авторизован ли пользователь
    if (!req.session.user || !req.session.user.id) {
        return res.redirect('/login?error=unauthorized');
    }

    const email = req.session.user.email;
    res.render('change_pass', { error: null, success: null, login: email });
});

app.post('/delete_account', (req, res) => {
    // Проверяем, авторизован ли пользователь
    if (!req.session.user || !req.session.user.id) {
        console.log('Session user not found or id missing:', req.session.user);
        return res.redirect('/login?error=unauthorized');
    }

    const userId = req.session.user.id;
    console.log('Attempting to delete user with id:', userId);

    // Удаляем пользователя из таблицы users
    pool.query(
        'DELETE FROM users WHERE id_user = ?',
        [userId],
        (dbErr, result) => {
            if (dbErr) {
                console.error('DB error during account deletion:', dbErr);
                return res.status(500).send('Ошибка при удалении учетной записи');
            }

            if (result.affectedRows === 0) {
                console.error('No user found with id:', userId);
                return res.status(404).send('Учетная запись не найдена');
            }

            console.log('User deleted successfully, affected rows:', result.affectedRows);

            // Завершаем сессию после удаления
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
                res.redirect('/login');
            });
        }
    );
});

// УПРАЖНЕНИЯ 

app.get('/exercises', authRequired, (req, res) => {
    pool.query(
        'SELECT id_exrc, name_exrc FROM exercises ORDER BY name_exrc',
        (err, rows) => {
        if (err) {
            console.error('Error fetching exercises:', err);
            return res.status(500).send('Ошибка при получении упражнений');
        }
        //console.log('Fetched exercises:', rows);
        res.render('exercises', { exercises: rows });
        }
    );
});

// Маршрут добавления упражнения
app.post('/exercises/add', authRequired, (req, res) => {
    const name = req.body.name_exrc && req.body.name_exrc.trim();
    if (!name) {
        return res.status(400).json({ success: false, message: 'Название упражнения не может быть пустым' });
    }
    pool.query(
        'INSERT INTO exercises (name_exrc) VALUES (?)',
        [name],
        (err, result) => {
        if (err) {
            console.error('DB error on INSERT:', err);
            return res.status(500).json({ success: false, message: 'Ошибка при добавлении упражнения' });
        }
        // возвращаем успех и новый ID
        res.json({ success: true, id: result.insertId });
        }
    );
});

// Маршрут удаления упражнения
app.post('/exercises/delete', authRequired, (req, res) => {
    console.log('→ DELETE request body:', req.body);
    const id = parseInt(req.body.id_exrc, 10);
    if (!id) {
        console.warn('Отсутсвует или неверный id_exrc');
        return res.status(400).json({ success: false, message: 'Неверный ID упражнения' });
    }
    pool.query(
        'DELETE FROM exercises WHERE id_exrc = ?',
        [id],
        (err, result) => {
        if (err) {
            console.error('Ошибка БД во время удаления:', err);
            return res
            .status(500)
            .json({ success: false, message: 'Ошибка сервера при удалении упражнения' });
        }
        console.log(`→ DELETE result for id=${id}:`, result);
        if (result.affectedRows === 0) {
            console.warn(`Упражнение с id=${id} не найдено`);
            return res
            .status(404)
            .json({ success: false, message: 'Упражнение не найдено в базе' });
        }
        // Всё ок
        res.json({ success: true });
        }
    );
});

// GET /exercises/search?term=…
app.get('/exercises/search', authRequired, (req, res) => {
    const term = (req.query.term || '').trim();
    const like = `%${term}%`;

  // Ищем сначала полное, потом частичное совпадение, потом всё остальное
    const sql = `
        SELECT id_exrc, name_exrc FROM exercises WHERE name_exrc LIKE ? ORDER BY (name_exrc = ?) DESC, (name_exrc LIKE ?) DESC, name_exrc`;

    pool.query(sql, [like, term, like], (err, rows) => {
        if (err) {
        console.error('Error searching exercises:', err);
        return res
            .status(500)
            .json({ success: false, message: 'Ошибка сервера при поиске' });
        }
        res.json({ success: true, exercises: rows });
    });
});

// НОВАЯ ТРЕНИРОВКА

// Словарь соответствий set_type → id_load_type
app.post('/add_routine', authRequired, urlencodedParser, (req, res) => {
  const userId    = req.session.user.id;
  const workoutId = req.body.workout_id ? parseInt(req.body.workout_id, 10) : null;
  const title     = req.body.title;
  const createdAt = req.body.created_at;
  let exercises   = req.body.exercises || [];

  if (!Array.isArray(exercises)) {
    exercises = [exercises];
  }
  if (!title) {
    return res.status(400).send('Название тренировки обязательно');
  }
  if (exercises.length === 0) {
    return res.status(400).send('Нужно добавить хотя бы одно упражнение');
  }

  const LOAD_TYPE_IDS = {
    weight_reps:   1,
    weight_time:   2,
    reps:          3,
    distance_time: 4,
    time:          5
  };

  // Если workoutId есть, значит редактируем. Иначе — создаём заново.
  if (workoutId) {
    // Проверка авторства
    pool.query(
      'SELECT id FROM user_workouts WHERE user_id = ? AND workout_id = ?',
      [userId, workoutId],
      (uwErr, uwRows) => {
        if (uwErr) {
          console.error('DB error checking auth:', uwErr);
          return res.status(500).send('Ошибка сервера');
        }
        if (uwRows.length === 0) {
          return res.status(403).send('Нет доступа');
        }

        // 1) Обновляем title и created_at
        pool.query(
          'UPDATE workouts SET title = ?, created_at = ? WHERE id_w = ?',
          [title, createdAt, workoutId],
          (wErr) => {
            if (wErr) {
              console.error('Error updating workout:', wErr);
              return res.status(500).send('Ошибка при сохранении');
            }

            // 2) Удаляем все старые workout_exercises и связанные подходы
            pool.query(
              'DELETE FROM workout_exercises WHERE id_workout = ?',
              [workoutId],
              (weDelErr) => {
                if (weDelErr) {
                  console.error('Error clearing old exercises:', weDelErr);
                  return res.status(500).send('Ошибка при пересохранении упражнений');
                }

                // 3) Параллельно вставляем новые exercise и подходы (как в создании)
                function insertExercise(i) {
                  if (i >= exercises.length) {
                    return res.redirect('/add_routine');
                  }
                  const ex = exercises[i];
                  const exId       = parseInt(ex.id_exercise, 10);
                  const loadTypeId = LOAD_TYPE_IDS[ex.set_type];
                  const displayOrder = i + 1;
                  if (!exId || !loadTypeId) {
                    console.warn('Invalid data at index', i, ex);
                    return insertExercise(i + 1);
                  }
                  // Вставляем новый workout_exercise
                  pool.query(
                    'INSERT INTO workout_exercises (id_workout, id_exercise, display_order) VALUES (?, ?, ?)',
                    [workoutId, exId, displayOrder],
                    (weErr, weRes) => {
                      if (weErr) {
                        console.error('Error inserting workout_exercises:', weErr);
                        return insertExercise(i + 1);
                      }
                      const wrktExrcId = weRes.insertId;
                      // Вставляем подходы
                      pool.query(
                        'INSERT INTO exercise_set_base (id_wrkt_exrc_set, set_num, id_load_type) VALUES (?, 1, ?)',
                        [wrktExrcId, loadTypeId],
                        (esbErr, esbRes) => {
                          if (esbErr) {
                            console.error('Error inserting exercise_set_base:', esbErr);
                            return insertExercise(i + 1);
                          }
                          const baseId = esbRes.insertId;
                          // Добавляем в таблицу-подтип
                          const reps     = ex.reps      ? parseInt(ex.reps, 10)       : null;
                          const weight   = ex.weight    ? parseFloat(ex.weight)       : null;
                          const duration = ex.duration_s? parseInt(ex.duration_s, 10) : null;
                          const distance = ex.distance  ? parseFloat(ex.distance)     : null;

                          let subtypeSql, subtypeParams;
                          switch (ex.set_type) {
                            case 'weight_reps':
                              subtypeSql    = 'INSERT INTO exercise_set_weight_reps (base_id, weight, reps) VALUES (?, ?, ?)';
                              subtypeParams = [baseId, weight, reps];
                              break;
                            case 'weight_time':
                              subtypeSql    = 'INSERT INTO exercise_set_weight_time (base_id, weight, duration_s) VALUES (?, ?, ?)';
                              subtypeParams = [baseId, weight, duration];
                              break;
                            case 'reps':
                              subtypeSql    = 'INSERT INTO exercise_set_reps (base_id, reps) VALUES (?, ?)';
                              subtypeParams = [baseId, reps];
                              break;
                            case 'distance_time':
                              subtypeSql    = 'INSERT INTO exercise_set_distance_time (base_id, distance, duration_s) VALUES (?, ?, ?)';
                              subtypeParams = [baseId, distance, duration];
                              break;
                            case 'time':
                              subtypeSql    = 'INSERT INTO exercise_set_time (base_id, duration_s) VALUES (?, ?)';
                              subtypeParams = [baseId, duration];
                              break;
                            default:
                              subtypeSql = null;
                          }
                          if (subtypeSql) {
                            pool.query(subtypeSql, subtypeParams, (stErr) => {
                              if (stErr) {
                                console.error('Error inserting subtype:', stErr);
                              }
                              insertExercise(i + 1);
                            });
                          } else {
                            insertExercise(i + 1);
                          }
                        }
                      );
                    }
                  );
                }
                insertExercise(0);
              }
            );
          }
        );
      }
    );
  } else {
    // Если нет workoutId → создаём новую (код, который был ранее)
    pool.query(
      'INSERT INTO workouts (title, created_at) VALUES (?, ?)',
      [title, createdAt],
      (wErr, wRes) => {
        if (wErr) {
          console.error('Error inserting workout:', wErr);
          return res.status(500).send('Ошибка при создании тренировки');
        }
        const newWorkoutId = wRes.insertId;

        // Привязываем к пользователю
        pool.query(
          'INSERT INTO user_workouts (user_id, workout_id) VALUES (?, ?)',
          [userId, newWorkoutId],
          () => {
            // даже если ошибка, продолжаем вставлять упражнения
            function insertExercise(i) {
              if (i >= exercises.length) {
                return res.redirect('/add_routine');
              }
              const ex = exercises[i];
              const exId       = parseInt(ex.id_exercise, 10);
              const loadTypeId = LOAD_TYPE_IDS[ex.set_type];
              const displayOrder = i + 1;
              if (!exId || !loadTypeId) {
                console.warn('Invalid data at index', i, ex);
                return insertExercise(i + 1);
              }

              pool.query(
                'INSERT INTO workout_exercises (id_workout, id_exercise, display_order) VALUES (?, ?, ?)',
                [newWorkoutId, exId, displayOrder],
                (weErr, weRes) => {
                  if (weErr) {
                    console.error('Error inserting workout_exercises:', weErr);
                    return insertExercise(i + 1);
                  }
                  const wrktExrcId = weRes.insertId;
                  pool.query(
                    'INSERT INTO exercise_set_base (id_wrkt_exrc_set, set_num, id_load_type) VALUES (?, 1, ?)',
                    [wrktExrcId, loadTypeId],
                    (esbErr, esbRes) => {
                      if (esbErr) {
                        console.error('Error inserting exercise_set_base:', esbErr);
                        return insertExercise(i + 1);
                      }
                      const baseId = esbRes.insertId;
                      const reps     = ex.reps      ? parseInt(ex.reps, 10)       : null;
                      const weight   = ex.weight    ? parseFloat(ex.weight)       : null;
                      const duration = ex.duration_s? parseInt(ex.duration_s, 10) : null;
                      const distance = ex.distance  ? parseFloat(ex.distance)     : null;

                      let subtypeSql, subtypeParams;
                      switch (ex.set_type) {
                        case 'weight_reps':
                          subtypeSql    = 'INSERT INTO exercise_set_weight_reps (base_id, weight, reps) VALUES (?, ?, ?)';
                          subtypeParams = [baseId, weight, reps];
                          break;
                        case 'weight_time':
                          subtypeSql    = 'INSERT INTO exercise_set_weight_time (base_id, weight, duration_s) VALUES (?, ?, ?)';
                          subtypeParams = [baseId, weight, duration];
                          break;
                        case 'reps':
                          subtypeSql    = 'INSERT INTO exercise_set_reps (base_id, reps) VALUES (?, ?)';
                          subtypeParams = [baseId, reps];
                          break;
                        case 'distance_time':
                          subtypeSql    = 'INSERT INTO exercise_set_distance_time (base_id, distance, duration_s) VALUES (?, ?, ?)';
                          subtypeParams = [baseId, distance, duration];
                          break;
                        case 'time':
                          subtypeSql    = 'INSERT INTO exercise_set_time (base_id, duration_s) VALUES (?, ?)';
                          subtypeParams = [baseId, duration];
                          break;
                        default:
                          subtypeSql = null;
                      }
                      if (subtypeSql) {
                        pool.query(subtypeSql, subtypeParams, (stErr) => {
                          if (stErr) {
                            console.error('Error inserting subtype:', stErr);
                          }
                          insertExercise(i + 1);
                        });
                      } else {
                        insertExercise(i + 1);
                      }
                    }
                  );
                }
              );
            }
            insertExercise(0);
          }
        );
      }
    );
  }
});




// СМЕНА ПАРОЛЯ

app.post('/change_pass', urlencodedParser, (req, res) => {
    // Проверяем, авторизован ли пользователь
    if (!req.session.user || !req.session.user.id) {
        return res.redirect('/login?error=unauthorized');
    }

    const userId = req.session.user.id;
    const oldPass = req.body.passOld;
    const newPass = req.body.passNew;

    // Проверка заполненности полей
    if (!oldPass || !newPass) {
        return res.render('change_pass', { error: 'empty', success: null, login: req.session.user.email });
    }

    // Получаем текущий хэш пароля из базы данных
    pool.query(
        'SELECT pass_hash FROM users WHERE id_user = ?',
        [userId],
        (dbErr, results) => {
            if (dbErr) {
                console.error('DB error during password change:', dbErr);
                return res.render('change_pass', { error: 'server', success: null, login: req.session.user.email });
            }

            if (results.length === 0) {
                console.error('User not found with id:', userId);
                return res.render('change_pass', { error: 'server', success: null, login: req.session.user.email });
            }

            const currentHash = results[0].pass_hash;

            // Сравниваем старый пароль с хэшем из базы
            bcrypt.compare(oldPass, currentHash, (bcryptErr, isMatch) => {
                if (bcryptErr) {
                    console.error('Bcrypt error during compare:', bcryptErr);
                    return res.render('change_pass', { error: 'server', success: null, login: req.session.user.email });
                }

                if (!isMatch) {
                    return res.render('change_pass', { error: 'wrongpass', success: null, login: req.session.user.email });
                }

                // Хешируем новый пароль
                bcrypt.hash(newPass, 12, (hashErr, newHash) => {
                    if (hashErr) {
                        console.error('Bcrypt error during hash:', hashErr);
                        return res.render('change_pass', { error: 'server', success: null, login: req.session.user.email });
                    }

                    // Обновляем пароль в базе данных
                    pool.query(
                        'UPDATE users SET pass_hash = ? WHERE id_user = ?',
                        [newHash, userId],
                        (updateErr, result) => {
                            if (updateErr) {
                                console.error('DB error during password update:', updateErr);
                                return res.render('change_pass', { error: 'server', success: null, login: req.session.user.email });
                            }

                            if (result.affectedRows === 0) {
                                console.error('No user updated with id:', userId);
                                return res.render('change_pass', { error: 'server', success: null, login: req.session.user.email });
                            }

                            console.log('Password updated successfully for user id:', userId);
                            res.render('change_pass', { error: null, success: true, login: req.session.user.email });
                        }
                    );
                });
            });
        }
    );
});

// МОИ ТРЕНИРОВКИ

// DELETE тренировки (через POST, поскольку мы не подключаем метод Override)
app.post('/routines/delete', authRequired, (req, res) => {
  const workoutId = parseInt(req.body.workout_id, 10);
  if (!workoutId) {
    return res.status(400).json({ success: false, message: 'Неверный ID тренировки' });
  }

  // Проверим, что текущий пользователь владеет этой записью (из user_workouts)
  const userId = req.session.user.id;
  pool.query(
    'SELECT id FROM user_workouts WHERE user_id = ? AND workout_id = ?',
    [userId, workoutId],
    (selErr, rows) => {
      if (selErr) {
        console.error('DB error checking ownership:', selErr);
        return res.status(500).json({ success: false, message: 'Ошибка сервера' });
      }
      if (rows.length === 0) {
        return res.status(403).json({ success: false, message: 'Нельзя удалять чужие тренировки' });
      }

      // Удаляем запись из user_workouts (CASCADE снимет связь)
      pool.query(
        'DELETE FROM user_workouts WHERE user_id = ? AND workout_id = ?',
        [userId, workoutId],
        (uwErr) => {
          if (uwErr) {
            console.error('Error deleting from user_workouts:', uwErr);
            return res.status(500).json({ success: false, message: 'Ошибка при удалении связи' });
          }
          // Далее удаляем саму тренировку из workouts (CASCADE удалит workout_exercises и exercise_set_base)
          pool.query(
            'DELETE FROM workouts WHERE id_w = ?',
            [workoutId],
            (wErr) => {
              if (wErr) {
                console.error('Error deleting workout:', wErr);
                return res.status(500).json({ success: false, message: 'Ошибка при удалении тренировки' });
              }
              res.json({ success: true });
            }
          );
        }
      );
    }
  );
});


// Test database connection
(function() {
    pool.query('SELECT 1', function(err, results) {
        if (err) {
        console.error('Database connection failed at', new Date().toLocaleString('ru-RU'), ':', err);
        return;
        }
        console.log('Database connection successful at', new Date().toLocaleString('ru-RU'));
    });
})();

app.listen(PORT, () => {
    console.log(`Сервер запущен: http://localhost:${PORT}`);
});