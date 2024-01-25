# dkim_verify.pl DKIM検証を理解するためのサンプルスクリプト

gmail, yahooなどのメールチェックの厳密化が行われました。
dkimが重要になるのですが、いまひとつ分からないので、実際にVerifyをするスクリプトを作りました。
基本的には動作するのですが、multi MIMEのメールボディの検証が間違っているようで、
メールによっては検証でエラーとなってしまいます。
RFC読み込めよ、というところなのですが、当初の目的は達成したと判断して、後回しにしています。

## ファイル

- dkim_verify.pl	# dkimの検証を行うサンプルスクリプト
- dp.pm				# デバッグ用の出力モジュール
- sample_mails		# 評価用のサンプルメール用のフォルダー
- working			# 検証に伴うワーキングファイル（排他制御ナシ）

## リファレンス

- [Email sender guidelines - Gmail Help](https://support.google.com/mail/answer/81126)
- [RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures 日本語訳](https://tex2e.github.io/rfc-translater/html/rfc6376.html)

- [SPF, DKIM, DMARCのDNSレコードの登録情報をdig, nslookupで確認する #mail - Qiita
送信ドメイン認証（SPF / DKIM / DMARC）の仕組みと、なりすましメール対策への活用法を徹底解説 – エンタープライズIT](https://qiita.com/kirikunix/items/dbf959ee1cb91ca899b0)
- [DKIM (Domainkeys Identified Mail) : 迷惑メール対策委員会](https://salt.iajapan.org/wpmu/anti_spam/admin/tech/explanation/dkim/)
- [RSA 鍵ペアを使って任意の文字列を暗号化・復号する #OpenSSL - Qiita](https://qiita.com/QUANON/items/79f06ca5ed57fa5c6c0e)
- [忘れないうちにOpenSSLでの暗号化と復号 （その２）](https://karte-m.cocolog-nifty.com/free/2022/08/post-4fd87e.html)
- [DKIM の署名を手動で付与してみる - QG Tech Blog](https://tech.quickguard.jp/posts/dkim/)
- [OpenSSLコマンドによる公開鍵暗号、電子署名の方法](https://qiita.com/kunichiko/items/3c0b1a2915e9dacbd4c1)

