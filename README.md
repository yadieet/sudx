[DEPRECATED]
# sudx
Run bash shell as another user with D-Bus enabled, useful for running GUI/X applications that need D-Bus.<br />
Sudx is modified from `SU` ([`util-linux`](https://www.kernel.org/pub/linux/utils/util-linux)).

### Usage:
 `sudx <user>`

<br />
#### `su --login` VS `sudx`, example `'pstree -u'` output :
<pre>bash───su(root)───bash<br /><br />bash───sudx(root)───dbus-run-sessio─┬─bash<br />                                    └─dbus-daemon</pre>
