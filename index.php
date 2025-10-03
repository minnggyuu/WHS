<?php
// config
$host = '127.0.0.1';
$user = 'web_server';
$pw = '';
$db   = 'mingyu_shopdb';

$conn = new mysqli($host, $user, $pw, $db);
if ($conn->connect_error) {
    die('DB Connection failed'); // 에러메시지 안보이게
}

// 서치
$q = isset($_GET['q']) ? $_GET['q'] : '';

$sql = "SELECT id, name, description, price, stock
        FROM products
        WHERE name LIKE '%" . $q . "%'";

// 실행
$res = $conn->query($sql);

// UI임
?>
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>취약한 쇼핑몰 - Blind SQLi 테스트</title>
  <style>
    body { font-family: sans-serif; margin: 40px; }
    .products { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
    .card { border: 1px solid #ddd; padding: 12px; border-radius: 8px; }
    .hint { background: #fffbea; border: 1px solid #f0e1a0; padding: 8px; border-radius: 6px; margin-bottom: 16px; }
    .footer { margin-top: 24px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h1>없는 거 빼고 다 팜</h1>

  <div class="hint">
    admin 비번 찾아보시오</br>
    <span style="font-size: 12px">??: 로그인이 없는데요</span>
  </div>

  <form method="get">
    <input type="text" name="q" placeholder="상품 검색 (ex: 까까)" value="<?php echo htmlspecialchars($q, ENT_QUOTES); ?>">
    <button type="submit">검색</button>
  </form>

  <?php
  // 있다 , 없다 둘 중에 하나 줌
  if ($q !== '') {
      if ($res && $res->num_rows > 0) {
          echo "<p>검색 결과가 존재합니다.</p>";
      } else {
          echo "<p>검색 결과가 없습니다.</p>";
      }
  }

  // 상품 그리드 렌더링
  echo '<div class="products">';
  if ($res && $res->num_rows > 0) {
      while ($row = $res->fetch_assoc()) {
          echo '<div class="card">';
          echo '<h3>' . htmlspecialchars($row['name'], ENT_QUOTES) . '</h3>';
          echo '<p>' . htmlspecialchars($row['description'], ENT_QUOTES) . '</p>';
          echo '<p>가격: ' . htmlspecialchars($row['price'], ENT_QUOTES) . ' | 재고: ' . htmlspecialchars($row['stock'], ENT_QUOTES) . '</p>';
          echo '</div>';
      }
  }
  echo '</div>';

  // 디버그를 위해 의도적으로 쿼리를 노출하지 않음(Blind 특성 유지)
  $conn->close();
  ?>
  <div class="footer">
    bsqli란 무엇인가
  </div>
</body>
</html>
