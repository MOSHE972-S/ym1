<?php
date_default_timezone_set('Asia/Jerusalem');
$logFile = __DIR__ . '/log.txt';

/**
 * כותב שורה ללוג (מסך וקובץ), מסנן פרטים רגישים.
 *
 * @param string $line השורה לכתיבה.
 */
function logLine(string $line): void {
    global $logFile;
    $time = date('Y-m-d H:i:s');

    // סינון פרטים רגישים מהשורה לפני כתיבה ללוג
    // מחליף שמות משתמש, סיסמאות, טוקנים ומספרי טלפון ב-***
    $sanitizedLine = $line;

    // סינון פרמטרים ב-URL (פחות רלוונטי ל-POST, אך נשאר ליתר בטחון ולהודעות שגיאה)
    $sanitizedLine = preg_replace('/username=[^&]+/', 'username=***', $sanitizedLine);
    $sanitizedLine = preg_replace('/password=[^&]+/', 'password=***', $sanitizedLine);
    $sanitizedLine = preg_replace('/token=[^&]+/', 'token=***', $sanitizedLine);

    // סינון שמות משתמש וסיסמאות בפורמט user:pass בתוך מחרוזת
    $sanitizedLine = preg_replace('/[0-9a-zA-Z]+:[0-9a-zA-Z]+/', '***:***', $sanitizedLine);

    // סינון מספרי טלפון (מניח פורמט של מספרים בלבד, לפחות 7 ספרות)
    $sanitizedLine = preg_replace('/\b\d{7,}\b/', '***', $sanitizedLine);

    // סינון ספציפי להודעות התחברות המציגות את שם המשתמש
    $sanitizedLine = preg_replace('/למשתמש: [0-9a-zA-Z]+/', 'למשתמש: ***', $sanitizedLine);
    $sanitizedLine = preg_replace('/עבור משתמש: [0-9a-zA-Z]+/', 'עבור משתמש: ***', $sanitizedLine);
    $sanitizedLine = preg_replace('/התחברות למשתמש [0-9a-zA-Z]+ נכשלה/', 'התחברות למשתמש *** נכשלה', $sanitizedLine);


    $fullLine = "[$time] $sanitizedLine\n";

    // הדפסה למסך (עם הסינון)
    echo $fullLine;

    // כתיבה לקובץ (עם הסינון)
    file_put_contents($logFile, $fullLine, FILE_APPEND);
}

/**
 * מבצע קריאת HTTP ל-URL נתון בשיטה מוגדרת, עם אופציה לשליחת נתונים.
 * מטפל בשגיאות. אימות SSL מופעל כברירת מחדל.
 *
 * @param string $url ה-URL ליעד.
 * @param string $method שיטת ה-HTTP (לדוגמה: 'GET', 'POST').
 * @param array|null $data מערך אסוציאטיבי של נתונים לשליחה (עבור POST כ-JSON, עבור GET כפרמטרים ב-URL).
 * @return string גוף התגובה.
 * @throws Exception אם הקריאה נכשלה או התקבלה תגובת שגיאה HTTP.
 */
function safeCall(string $url, string $method = 'GET', array $data = null): string {
    $options = [
        'ssl' => [
            // אימות אישורי SSL מופעל כברירת מחדל - חשוב לאבטחה!
            // אין צורך להגדיר verify_peer ו-verify_peer_name ל-true באופן מפורש,
            // אלא אם כן יש צורך בהגדרות ספציפיות יותר. ברירת המחדל היא true.
        ],
        'http' => [
            'method' => $method,
            'ignore_errors' => true, // מאפשר קבלת גוף תגובה גם אם התקבל סטטוס שגיאה HTTP
        ],
    ];

    if ($method === 'POST') {
        $options['http']['header'] = 'Content-Type: application/json';
        if ($data !== null) {
            $options['http']['content'] = json_encode($data);
        }
    } elseif ($method === 'GET') {
        if ($data !== null) {
             // עבור GET, הוסף את הנתונים כפרמטרים ל-URL
             $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($data);
        }
        // אין צורך ב-'content' או 'header' עבור GET עם נתונים ב-URL
    } else {
         // ניתן להוסיף תמיכה בשיטות נוספות כאן, או לזרוק שגיאה
         throw new Exception("Unsupported HTTP method: " . $method);
    }

    // יצירת הקונטקסט עם האפשרויות המוגדרות
    $context = stream_context_create($options);

    // ביצוע הקריאה ל-URL
    // הסימן @ מדכא אזהרות ושגיאות מ-file_get_contents (כמו שגיאות SSL אם verify_peer מופעל ויש בעיה)
    // אנו מטפלים בשגיאות באופן ידני לאחר מכן.
    $resp = @file_get_contents($url, false, $context);

    // בדיקת סטטוס קוד HTTP אם ignore_errors מופעל
    $http_status = null;
    // file_get_contents מאכלס את המשתנה הגלובלי $http_response_header
    if (isset($http_response_header)) {
        // מחלץ את סטטוס הקוד מראש ה-HTTP הראשון
        preg_match('/HTTP\/[\d\.]+\s+(\d+)/', $http_response_header[0], $matches);
        if (isset($matches[1])) {
            $http_status = (int)$matches[1];
        }
    }

    // בדיקה אם התגובה היא false (שגיאת רשת/חיבור) או אם התקבל סטטוס שגיאה HTTP (400 ומעלה)
    // הודעת השגיאה כאן תהיה גנרית ולא תכלול את גוף התגובה המלא מה-API
    if ($resp === false || ($http_status !== null && $http_status >= 400)) {
        $error = error_get_last();
        $errorMessage = $error ? $error['message'] : 'שגיאה לא ידועה';
        $statusMessage = ($http_status !== null) ? " HTTP Status: " . $http_status : "";
        throw new Exception("שגיאה בקריאה ל-URL: " . $url . ". פרטי שגיאה: " . $errorMessage . $statusMessage . ". (גוף תגובה לא נרשם בלוג)");
    }

    return $resp;
}


/**
 * מתחבר ל-API ומקבל טוקן זמני.
 *
 * @param string $baseUrl ה-URL הבסיסי של ה-API.
 * @param string $username שם המשתמש (מספר טלפון).
 * @param string $password הסיסמה.
 * @return string הטוקן הזמני שהתקבל.
 * @throws Exception אם ההתחברות נכשלה או שהטוקן לא התקבל.
 */
function getToken(string $baseUrl, string $username, string $password): string {
    // הודעת הלוג כאן תסונן על ידי logLine
    logLine("🔑 מנסה להתחבר למשתמש: " . substr($username, 0, 3) . '***'); // מציג חלק משם המשתמש בלוג
    // שימוש ב-safeCall עם POST ונתונים בגוף הבקשה
    $resp = safeCall($baseUrl . "Login", 'POST', [
        'username' => $username,
        'password' => $password
    ]);

    $json = json_decode($resp, true);

    if (is_array($json) && strtoupper(($json['responseStatus'] ?? '')) === 'OK' && !empty($json['token'])) {
        // הודעת הלוג כאן לא תציג את הטוקן עצמו, רק את ההצלחה
        logLine("✅ התחברות הצליחה. התקבל טוקן.");
        return $json['token'];
    } else {
        // הודעת השגיאה כאן גנרית ולא תכלול את גוף התגובה המלא
        throw new Exception("❌ התחברות למשתמש נכשלה או שהטוקן לא התקבל.");
    }
}


/**
 * מוחק קובץ ymgr באמצעות טוקן.
 *
 * @param string $baseUrl ה-URL הבסיסי של ה-API.
 * @param string $token הטוקן לשימוש.
 * @param string $ymgrFilePath הנתיב לקובץ ymgr למחיקה.
 * @throws Exception אם מחיקת הקובץ נכשלה.
 */
function deleteFile(string $baseUrl, string $token, string $ymgrFilePath): void {
    // הודעת הלוג כאן תסונן על ידי logLine (תסיר את הטוקן מה-URL אם יופיע שם)
    logLine("🗑️ מנסה למחוק קובץ באמצעות טוקן...");
    // שימוש ב-safeCall עם POST ונתונים בגוף הבקשה
    try {
        $resp = safeCall($baseUrl . "FileAction", 'POST', [
            'token' => $token,
            'what' => $ymgrFilePath, // משתמש בנתיב הקובץ שהתקבל כפרמטר
            'action' => 'delete'
        ]);
        $json = json_decode($resp, true);
        if (is_array($json) && strtoupper(($json['responseStatus'] ?? '')) === 'OK') {
            logLine("✅ FileAction delete הצליח.");
        } else {
            // מציג הודעה גנרית במקרה של כישלון
            logLine("⚠️ FileAction delete נכשל או לא ברור.");
        }
    } catch (Exception $e) {
        // לוכד שגיאות מ-safeCall גם כאן. הודעת השגיאה תהיה גנרית.
        logLine("❌ שגיאה במהלך מחיקת קובץ.");
    }
}

/* ──────────────────────────────────────────────────────────
    הַדְבֵּק כאן את הפונקציה setupNewUser כפי שנשלחה לך
    (פונקציה שמכילה את כל חמשת הצעדים).
    הפונקציה עודכנה כדי לקבל טוקן זמני עבור המשתמש הנוכחי
    ולבצע קריאות API בשיטת POST עם JSON.
────────────────────────────────────────────────────────── */
/**
 * מגדיר את ההרחבות והקבצים עבור משתמש חדש באמצעות טוקן זמני.
 *
 * @param string $baseUrl ה-URL הבסיסי של ה-API.
 * @param string $user שם המשתמש (מספר טלפון) של המשתמש שמוגדר.
 * @param string $pass הסיסמה של המשתמש שמוגדר.
 * @param string $phone מספר הטלפון שיוכנס ל-WhiteList.ini.
 * @param string $routingYemotNumber מספר הניתוב למערכת.
 * @param string $routing1800Number מספר הניתוב ל-1800.
 * @throws Exception אם אחת מקריאות ה-API נכשלת.
 */
function setupNewUser(string $baseUrl, string $user, string $pass, string $phone, string $routingYemotNumber, string $routing1800Number): void {
    // הודעת הלוג כאן תסונן על ידי logLine
    logLine("📦 התחלת הגדרות עבור משתמש: " . substr($user, 0, 3) . '***' . ", טלפון: " . substr($phone, 0, 3) . '***');

    // מקבל טוקן זמני עבור המשתמש הספציפי הזה
    $userTempToken = getToken($baseUrl, $user, $pass);
    // הודעת הלוג כאן לא תציג את הטוקן עצמו, רק את ההצלחה
    logLine("✅ התקבל טוקן זמני עבור משתמש.");

    // 1) ivr2: UpdateExtension (POST with JSON)
    logLine("🛠️ שלב 1: הגדרת ivr2:");
    $resp1 = safeCall($baseUrl . "UpdateExtension", 'POST', [
        'token' => $userTempToken, // משתמש בטוקן הזמני
        'path' => "ivr2:",
        'type' => "routing_yemot",
        'routing_yemot_number' => $routingYemotNumber, // משתמש במספר שהתקבל כפרמטר
        'white_list_error_goto' => "/1",
        'white_list' => "yes"
    ]);
    $json1 = json_decode($resp1, true);
    if (!is_array($json1) || strtoupper(($json1['responseStatus'] ?? '')) !== 'OK') {
        // הודעת השגיאה כאן גנרית
        throw new Exception("❌ UpdateExtension נכשל עבור משתמש (ivr2:).");
    }
    logLine("✅ UpdateExtension הצליח עבור משתמש (ivr2:)");

    // 2) ivr2:1 routing_1800 (POST with JSON)
    logLine("🛠️ שלב 2: הגדרת ivr2:1");
    $resp2 = safeCall($baseUrl . "UpdateExtension", 'POST', [
        'token' => $userTempToken, // משתמש בטוקן הזמני
        'path' => "ivr2:1",
        'type' => "routing_1800",
        'routing_1800' => $routing1800Number // משתמש במספר שהתקבל כפרמטר
    ]);
    $json2 = json_decode($resp2, true);
    if (!is_array($json2) || strtoupper(($json2['responseStatus'] ?? '')) !== 'OK') {
        // הודעת השגיאה כאן גנרית
        throw new Exception("❌ UpdateExtension נכשל עבור משתמש (ivr2:1).");
    }
    logLine("✅ UpdateExtension הצליח עבור משתמש (ivr2:1)");

    // 3) UploadTextFile של M1102.tts (GET with URL params - כפי שביקש המשתמש להשאיר העלאות קבצים)
    logLine("🛠️ שלב 3: העלאת M1102.tts");
    $resp3 = safeCall($baseUrl . "UploadTextFile", 'GET', [
        'token' => $userTempToken, // משתמש בטוקן הזמני
        'what' => "ivr2:/M1102.tts",
        'contents' => " " // תוכן ריק כפי שהיה
    ]);
    $json3 = json_decode($resp3, true);
    if (!is_array($json3) || strtoupper(($json3['responseStatus'] ?? '')) !== 'OK') {
        // הודעת השגיאה כאן גנרית
        throw new Exception("❌ UploadTextFile נכשל עבור משתמש (M1102.tts).");
    }
    logLine("✅ UploadTextFile הצליח עבור משתמש M1102.tts");

    // 4) FileAction move ל-M1102.wav (POST with JSON)
    logLine("🛠️ שלב 4: העברת M1102.tts ל-M1102.wav");
    $resp4 = safeCall($baseUrl . "FileAction", 'POST', [
        'token' => $userTempToken, // משתמש בטוקן הזמני
        'what' => "ivr2:/M1102.tts",
        'action' => "move",
        'target' => "ivr2:/M1102.wav"
    ]);
    $json4 = json_decode($resp4, true);
    if (!is_array($json4) || strtoupper(($json4['responseStatus'] ?? '')) !== 'OK') {
        // הודעת השגיאה כאן גנרית
        throw new Exception("❌ FileAction move נכשל עבור משתמש.");
    }
    logLine("✅ FileAction move הצליח עבור משתמש");

    // 5) UploadTextFile של WhiteList.ini עם טלפון (GET with URL params - כפי שביקש המשתמש להשאיר העלאות קבצים)
    logLine("🛠️ שלב 5: העלאת WhiteList.ini");
    $resp5 = safeCall($baseUrl . "UploadTextFile", 'GET', [
        'token' => $userTempToken, // משתמש בטוקן הזמני
        'what' => "ivr2:WhiteList.ini",
        'contents' => $phone // הטלפון מוכנס לתוכן הקובץ, לא ללוג ישירות
    ]);
    $json5 = json_decode($resp5, true);
    if (!is_array($json5) || strtoupper(($json5['responseStatus'] ?? '')) !== 'OK') {
        // הודעת השגיאה כאן גנרית
        throw new Exception("❌ UploadTextFile WhiteList.ini נכשל עבור משתמש.");
    }
    // הודעת הלוג כאן תסונן על ידי logLine (תסיר את הטלפון)
    logLine("✅ UploadTextFile הצליח עבור משתמש WhiteList.ini (טלפון: " . substr($phone, 0, 3) . '***' . ")");

    logLine("🎉 סיום הגדרות עבור משתמש\n");
}

// —————————————————────────────────────────────────────────———
// שִׂיא הִתְחָלָה: כאן מתחיל הקטע שמוריד ומעבד את ה-JSON
logLine("🚀 התחלת תהליך קבלת נתונים מהמערכת החיצונית...");

// מקבל את ה-URL הבסיסי של ה-API ממשתנה הסביבה
$ymApiBaseUrl = getenv('YM_API_BASE_URL');
if (!$ymApiBaseUrl) {
    logLine("❌ לא נמצא YM_API_BASE_URL. ודא שהגדרת את YM_API_BASE_URL ב-GitHub Secrets.");
    exit(1);
}
// מוודא שה-URL מסתיים בלוכסן (/)
if (substr($ymApiBaseUrl, -1) !== '/') {
    $ymApiBaseUrl .= '/';
}

// מקבל את נתיב קובץ ה-ymgr ממשתנה הסביבה
$ymgrFilePath = getenv('YM_YMGR_FILE_PATH');
if (!$ymgrFilePath) {
    logLine("❌ לא נמצא YM_YMGR_FILE_PATH. ודא שהגדרת את YM_YMGR_FILE_PATH ב-GitHub Secrets.");
    exit(1);
}

// מקבל את מספר הניתוב למערכת ממשתנה הסביבה
$routingYemotNumber = getenv('YM_ROUTING_YEMOT_NUMBER');
if (!$routingYemotNumber) {
    logLine("❌ לא נמצא YM_ROUTING_YEMOT_NUMBER. ודא שהגדרת את YM_ROUTING_YEMOT_NUMBER ב-GitHub Secrets.");
    exit(1);
}

// מקבל את מספר הניתוב ל-1800 ממשתנה הסביבה
$routing1800Number = getenv('YM_ROUTING_1800_NUMBER');
if (!$routing1800Number) {
    logLine("❌ לא נמצא YM_ROUTING_1800_NUMBER. ודא שהגדרת את YM_ROUTING_1800_NUMBER ב-GitHub Secrets.");
    exit(1);
}


// מקבל את שם המשתמש והסיסמה מהמשתנה הסביבתי YM_TOKEN
$ymTokenEnv = getenv('YM_TOKEN');
if (!$ymTokenEnv) {
    logLine("❌ לא נמצא YM_TOKEN. ודא שהגדרת את YM_TOKEN ב-GitHub Secrets בפורמט username:password.");
    exit(1);
}

// מפריד את שם המשתמש והסיסמה
$tokenParts = explode(':', $ymTokenEnv, 2);
if (count($tokenParts) !== 2) {
    logLine("❌ פורמט YM_TOKEN שגוי. יש להשתמש בפורמט username:password.");
    exit(1);
}
$mainUser = $tokenParts[0];
$mainPass = $tokenParts[1];

$mainTempToken = null; // משתנה לאחסון הטוקן הראשי

try {
    // 1) מתחבר עם המשתמש הראשי כדי לקבל טוקן זמני (POST with JSON)
    // הודעת הלוג כאן תסונן על ידי logLine
    $mainTempToken = getToken($ymApiBaseUrl, $mainUser, $mainPass);
    // הודעת הלוג כאן לא תציג את הטוקן עצמו, רק את ההצלחה
    logLine("✅ התקבל טוקן ראשי עבור שליפת קובץ.");

    // 2) fetch JSON באמצעות הטוקן הראשי (GET with URL params - נשאר כפי שהיה)
    logLine("⬇️ מנסה לשלוף קובץ JSON באמצעות הטוקן הראשי...");
    $response = safeCall($ymApiBaseUrl . "RenderYMGRFile", 'GET', [
        'token' => $mainTempToken, // משתמש בטוקן הראשי
        'wath' => $ymgrFilePath, // משתמש בנתיב הקובץ שהתקבל ממשתנה הסביבה
        'convertType' => "json",
        'notLoadLang' => "0"
    ]);
    $json = json_decode($response, true);

    // הודעת השגיאה כאן גנרית ולא תכלול את גוף התגובה המלא
    if (!is_array($json) || !isset($json['data'])) {
        throw new Exception("JSON לא תקין או חסר 'data'.");
    }

    $data = $json['data'];
    if (count($data) === 0) {
        logLine("ℹ️ אין רשומות בקובץ.");
    } else {
        $processedCount = 0; // מונה רשומות מעובדות
        $maxRecords = 20; // מגדיר מגבלה של 20 רשומות

        logLine("📚 נמצאו " . count($data) . " רשומות לעיבוד. מעבד עד $maxRecords רשומות.");

        foreach ($data as $i => $entry) {
            // בדיקה האם הושגה מגבלת הרשומות לעיבוד
            if ($processedCount >= $maxRecords) {
                logLine("⚠️ הושגה מגבלת $maxRecords רשומות לעיבוד. עוצר.");
                break; // עוצר את הלולאה
            }

             // חילוץ נתוני המשתמש מכל רשומה (מערך אסוציאטיבי)
             // שימוש ב-?? null כדי לוודא שהמשתנה מוגדר גם אם השדה חסר ב-JSON
            $user = $entry['P050'] ?? null;
            $pass = $entry['P051'] ?? null;
            $phone = $entry['P052'] ?? null;

            // בדיקה האם הרשומה שלמה - בודק אם הערכים הם null או מחרוזת ריקה בלבד.
            // ערכים כמו "0" או "false" ייחשבו תקינים.
            if ($user === null || $user === "" ||
                $pass === null || $pass === "" ||
                $phone === null || $phone === "") {
                logLine("⚠️ רשומה $i (אינדקס בלולאה) לא שלמה (P050/P051/P052 חסרים או ריקים לחלוטין). מדלג על רשומה זו.");
                continue; // מדלג על רשומה לא תקינה וממשיך הלאה
            }

            // בלוק try...catch פנימי לטיפול בשגיאות עבור כל משתמש בנפרד
            try {
                // קריאה לפונקציה שמגדירה את המשתמש (כוללת את קריאות ה-API השונות)
                // מעביר את מספרי הניתוב כפרמטרים
                setupNewUser($ymApiBaseUrl, $user, $pass, $phone, $routingYemotNumber, $routing1800Number);
                $processedCount++; // מגדיל את המונה רק אם ההגדרה הצליחה ללא שגיאה
            } catch (Exception $userSetupException) {
                 // לכידת שגיאה ספציפית להגדרת המשתמש הנוכחי. הודעת הלוג גנרית.
                logLine("❌ שגיאה בהגדרת משתמש.");
                // הסקריפט ימשיך ללולאה הבאה כדי לנסות לעבד משתמשים אחרים
            }
        }
        logLine("✅ סיום עיבוד רשומות. סך הכל עובדו: $processedCount.");
    }
} catch (Exception $e) {
    // לכידת שגיאה כללית בתהליך הראשי. הודעת הלוג גנרית.
    logLine("❌ שגיאה כללית בתהליך הראשי.");
} finally {
    // תמיד מוודאים שמוחקים את הקובץ, אם הטוקן הראשי התקבל בהצלחה
    if ($mainTempToken) {
        deleteFile($ymApiBaseUrl, $mainTempToken, $ymgrFilePath); // מעביר את נתיב הקובץ כפרמטר
    } else {
        logLine("⚠️ לא ניתן למחוק קובץ כי הטוקן הראשי לא התקבל.");
    }
    logLine("🏁 סיום התהליך.");
}
?>
