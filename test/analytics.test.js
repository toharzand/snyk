var test = require('tape');
var proxyquire = require('proxyquire');
var sinon = require('sinon');
var snyk = require('../lib');

test('analytics disabled', function (t) {
  var spy = sinon.spy();
  var old = snyk.config.get('disable-analytics');
  snyk.config.set('disable-analytics', '1');
  var analytics = proxyquire('../lib/analytics', {
    './request': spy,
  });

  t.plan(1);
  analytics().then(function () {
    t.equal(spy.called, false, 'the request should not have been made');
    if (old === undefined) {
      snyk.config.del('disable-analytics');
    } else {
      snyk.config.set('disable-analytics', old);
    }
  });
});

test('analytics', function (t) {
  var spy = sinon.spy();
  var old = snyk.config.get('disable-analytics');
  snyk.config.del('disable-analytics');
  var analytics = proxyquire('../lib/analytics', {
    './request': spy,
  });

  t.plan(1);

  analytics.add('foo', 'bar');

  analytics({
    command: '__test__',
    args: [],
  }).then(function () {
    var body = spy.lastCall.args[0].body.data;
    t.deepEqual(Object.keys(body).sort(), ['command', 'version', 'id', 'ci', 'metadata', 'args'].sort(), 'keys as expected');
    if (old === undefined) {
      snyk.config.del('disable-analytics');
    } else {
      snyk.config.set('disable-analytics', old);
    }
  });

});