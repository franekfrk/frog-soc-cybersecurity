import time
import test_features

class UpdateTests(test_features.FeatureTests):
    def test_notes_token_canonical_escape_delete(self):
        a=self.app; ip='192.0.2.1'
        fields={'ip':['::ffff:'+ip], 'label':['<script>'], 'note':['hello'], 'token':[a.admin_token('note:'+ip)]}
        a.change_note(fields)
        page=a.ip_page(ip)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn('hello',page)
        fields['token']=['invalid']
        with self.assertRaises(PermissionError): a.change_note(fields)
        fields.update(label=[''],note=[''],token=[a.admin_token('note:'+ip)])
        a.change_note(fields)
        with a.db_connect() as c: self.assertEqual(c.execute('SELECT COUNT(*) FROM ip_notes').fetchone()[0],0)

    def test_comparison_boundaries_and_seen(self):
        a=self.app; now=time.time()
        with a.db_connect() as c:
            c.executemany('INSERT INTO events VALUES (?,?,?,?)',[(now-10,'192.0.2.1','/new','GET'),(now-90000,'192.0.2.2','/old','GET')])
        self.assertEqual(a.period_counts(now-86400,now)[:2],(1,1))
        self.assertEqual(a.period_counts(now-172800,now-86400)[:2],(1,1))
        self.assertIn('/new',a.updates_page())
        until=str(now)
        a.change_note({'action':['seen'],'until':[until],'token':[a.admin_token('seen:'+until)]})
        self.assertNotIn('/new</td>',a.updates_page())
        with a.db_connect() as c: self.assertEqual(float(a.meta_get(c,'updates_seen')),now)
        self.assertIn('Porównania okresów',a.comparison_page({'period':'7d'}))
        with self.assertRaises(ValueError): a.comparison_page({'period':'bad'})
